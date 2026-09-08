use super::*;
use crate::git::RepositoryStats;
use anyhow::{Context, Result};
use fancy_regex::Regex;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use tracing::info;

pub struct PatternEngine {
    compiled_patterns: Vec<(Regex, VulnerabilityPattern)>,
}

/// Max size of the per-finding diff snippet carried into the (compact) agent
/// report. The changed-lines diff is already artifact-filtered, so this is
/// mostly signal; ~16 KB covers a few hundred changed lines — enough for large
/// security fixes while keeping the report bounded. The full diff (capped at
/// 256 KB in the git layer) remains available on `CommitInfo`.
const DIFF_SNIPPET_CHARS: usize = 16_000;

/// Truncate a diff to `max` chars on a line boundary, marking the cut.
fn diff_snippet(diff: &str, max: usize) -> String {
    if diff.chars().count() <= max {
        return diff.to_string();
    }
    let mut out = String::with_capacity(max + 16);
    for ch in diff.chars() {
        if out.len() >= max {
            break;
        }
        out.push(ch);
    }
    // Back off to the last complete line so we don't cut a hunk mid-line.
    if let Some(nl) = out.rfind('\n') {
        out.truncate(nl + 1);
    }
    out.push_str("[snippet truncated — see full diff]\n");
    out
}

/// Non-source paths that must not drive findings or the score: build output,
/// translations, vendored code, lockfiles.
pub fn is_artifact(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.starts_with("dist/")
        || p.contains("/dist/")
        || p.ends_with(".map")
        || p.ends_with(".license")
        || p.ends_with(".min.js")
        || p.ends_with(".min.css")
        || p.contains("/l10n/")
        || p.starts_with("3rdparty/")
        || p.starts_with("vendor/")
        || p.contains("/vendor/")
        || p.contains("node_modules/")
        || p.ends_with("-lock.json")
        || p.ends_with("composer.lock")
        // Dependency manifests: a roll commit quotes upstream changelogs, so it
        // matches vulnerability vocabulary without touching this project's code.
        || p == "deps"
        || p.ends_with("/deps")
        || p.ends_with("go.mod")
        || p.ends_with("go.sum")
        || p.ends_with("cargo.toml")
        || p.ends_with("cargo.lock")
        || p.ends_with("package.json")
        || p.ends_with("yarn.lock")
        || p.ends_with("pnpm-lock.yaml")
        || p.ends_with("requirements.txt")
        || p.ends_with(".lock")
}

fn is_test(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("/tests/")
        || p.contains("/test/")
        || p.contains("test.php")
        || p.contains(".test.")
        || p.contains(".spec.")
        || p.ends_with("_test.go")
}

/// A real source file: not an artifact and not a test. Tests are corroboration,
/// not the primary changed surface.
pub fn is_source_file(path: &str) -> bool {
    !is_artifact(path) && !is_test(path)
}

/// Normalize a commit subject so identical backports across branches collapse
/// to one key: first line, lowercased, trailing `(#1234)` PR ref stripped.
fn normalize_subject(message: &str) -> String {
    let mut line = message.lines().next().unwrap_or("").trim().to_ascii_lowercase();
    if let Some(pos) = line.rfind("(#") {
        if line.ends_with(')') {
            line.truncate(pos);
        }
    }
    line.trim().to_string()
}

impl PatternEngine {
    pub fn new(pattern_set: &str) -> Result<Self> {
        let patterns = match pattern_set {
            "memorysafety" => Self::get_memory_safety_patterns(),
            "crypto" => Self::get_crypto_patterns(),
            "web" | "php" => Self::get_web_patterns(),
            "workerd" | "cpp" => Self::get_workerd_patterns(),
            "autovuln" => Self::get_autovuln_patterns(),
            "all" => default_patterns(),
            _ => Self::get_vuln_patterns(),
        };

        info!("Loading {} vulnerability patterns", patterns.len());

        let compiled_patterns = patterns
            .iter()
            .map(|pattern| {
                let regex = Regex::new(&pattern.pattern)
                    .with_context(|| format!("Failed to compile pattern: {}", pattern.name))?;
                Ok((regex, pattern.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { compiled_patterns })
    }

    pub async fn scan_repository(
        &self,
        _repo_path: &Path,
        git_stats: &RepositoryStats,
    ) -> Result<Vec<VulnerabilityFinding>> {
        info!("Starting vulnerability pattern scan...");

        let pb = ProgressBar::new(git_stats.commit_history.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:30.cyan/blue}] {pos}/{len} commits ({eta})")?
                .progress_chars("=>-"),
        );

        let findings: Vec<_> = git_stats
            .commit_history
            .par_iter()
            .filter_map(|commit| {
                pb.inc(1);
                self.analyze_commit(commit).ok().flatten()
            })
            .collect();

        pb.finish_with_message("Scan completed");

        // Collapse identical fixes backported across branches into one finding.
        let findings = Self::cluster_backports(findings);

        info!("Found {} potential vulnerabilities", findings.len());
        Ok(findings)
    }

    fn analyze_commit(
        &self,
        commit: &crate::git::CommitInfo,
    ) -> Result<Option<VulnerabilityFinding>> {
        let mut patterns_matched = Vec::new();
        let mut cve_references = Vec::new();

        let message = &commit.message;
        let message_lc = message.to_ascii_lowercase();
        let diff = &commit.diff;
        let diff_lc = diff.to_ascii_lowercase();

        for (regex, pattern) in &self.compiled_patterns {
            // Language gate: skip a language-specific rule unless the commit
            // actually touches a matching source file (keeps the workerd/KJ C++
            // rules from firing on a PHP/JS repo, and vice versa).
            if !pattern.lang_ext.is_empty() {
                let touches_lang = commit.files_changed.iter().any(|f| {
                    let fl = f.to_ascii_lowercase();
                    pattern.lang_ext.iter().any(|ext| fl.ends_with(ext.as_str()))
                });
                if !touches_lang {
                    continue;
                }
            }

            // Which text(s) does this pattern look at?
            let haystacks: &[(&str, &str, &str)] = match pattern.target {
                MatchTarget::Message => &[("commit_message", message, &message_lc)],
                MatchTarget::Diff => &[("diff", diff, &diff_lc)],
                MatchTarget::Both => &[
                    ("commit_message", message, &message_lc),
                    ("diff", diff, &diff_lc),
                ],
            };

            for (label, text, text_lc) in haystacks {
                if text.is_empty() {
                    continue;
                }
                let Ok(Some(captures)) = regex.captures(text) else {
                    continue;
                };

                // Context gating: require a security-relevant nearby term and
                // suppress on a benign one (drops MD5-as-integrity false
                // positives).
                if !pattern.require_near.is_empty()
                    && !pattern.require_near.iter().any(|n| text_lc.contains(n))
                {
                    continue;
                }
                if pattern.suppress_near.iter().any(|n| text_lc.contains(n)) {
                    continue;
                }

                let matched_text = captures.get(0).unwrap().as_str().to_string();
                if pattern.name == "CVE Reference" {
                    if let Some(cve_id) = captures.get(1) {
                        cve_references.push(format!("CVE-{}", cve_id.as_str()));
                    }
                }

                patterns_matched.push(PatternMatch {
                    pattern_name: pattern.name.clone(),
                    matched_text,
                    severity: pattern.severity.clone(),
                    category: pattern.category.clone(),
                    file_path: label.to_string(),
                    line_number: None,
                    context: (*text).chars().take(400).collect(),
                    cve_references: cve_references.clone(),
                });
                break; // one match per pattern is enough
            }
        }

        if patterns_matched.is_empty() {
            return Ok(None);
        }

        let source_files: usize = commit
            .files_changed
            .iter()
            .filter(|f| is_source_file(f))
            .count();

        let risk_score = self.calculate_risk_score(&patterns_matched, source_files);

        Ok(Some(VulnerabilityFinding {
            commit_id: commit.id.clone(),
            commit_message: commit.message.clone(),
            author: commit.author.clone(),
            date: commit.authored_date,
            files_changed: commit.files_changed.clone(),
            patterns_matched,
            risk_score,
            cve_references,
            backport_count: 1,
            diff_snippet: diff_snippet(&commit.diff, DIFF_SNIPPET_CHARS),
        }))
    }

    fn severity_weight(sev: &Severity) -> f64 {
        match sev {
            Severity::Critical => 9.0,
            Severity::High => 7.0,
            Severity::Medium => 5.0,
            Severity::Low => 3.0,
            Severity::Info => 1.0,
        }
    }

    /// Evidence-based score. Drives on the strongest signal, not commit churn:
    /// diff-signature matches are trusted, message-only matches are discounted,
    /// and commits that touch no source file (artifacts/tests only) are floored.
    fn calculate_risk_score(&self, patterns: &[PatternMatch], source_files: usize) -> f64 {
        let base = patterns
            .iter()
            .map(|p| Self::severity_weight(&p.severity))
            .fold(0.0_f64, f64::max);

        let has_diff_match = patterns.iter().any(|p| p.file_path == "diff");
        let has_msg_match = patterns.iter().any(|p| p.file_path == "commit_message");
        let has_cve = patterns.iter().any(|p| p.pattern_name == "CVE Reference");

        let mut score = base;

        // No source touched → almost certainly noise: a dependency roll or a
        // translation commit quoting upstream vocabulary. This is the only
        // discount, and it is the same condition that floors the severity.
        //
        // A message-only match is NOT weak evidence here: mining commit
        // messages is what this tool does, and the vocabulary patterns are
        // high-precision. Halving them made every genuine "fix UAF" commit
        // render as a mid-yellow 4.5 while its severity said Critical, so the
        // badge and the score contradicted each other on the common case.
        if source_files == 0 {
            score *= 0.3;
        }
        // Message vocabulary + a corroborating code-level signature agree.
        if has_diff_match && has_msg_match {
            score *= 1.15;
        }
        if has_cve {
            score *= 1.5;
        }

        score.min(10.0)
    }

    /// Merge commits that share a normalized subject (same fix backported to
    /// several stable branches) into one representative finding, recording the
    /// backport count and boosting the score — a fix shipped to N branches is a
    /// strong CVE signal.
    fn cluster_backports(findings: Vec<VulnerabilityFinding>) -> Vec<VulnerabilityFinding> {
        let mut groups: HashMap<String, Vec<VulnerabilityFinding>> = HashMap::new();
        for f in findings {
            let key = normalize_subject(&f.commit_message);
            groups.entry(key).or_default().push(f);
        }

        let mut out = Vec::with_capacity(groups.len());
        for (_key, mut group) in groups {
            // Representative = highest-scoring commit in the cluster.
            group.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));
            let count = group.len();
            let mut rep = group.into_iter().next().unwrap();
            rep.backport_count = count;
            if count > 1 {
                // +0.5 per extra branch, capped — a widely backported fix is
                // almost certainly a real, triaged vulnerability.
                rep.risk_score = (rep.risk_score + (count as f64 - 1.0) * 0.5).min(10.0);
            }
            out.push(rep);
        }

        out.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));
        out
    }

    fn get_memory_safety_patterns() -> Vec<VulnerabilityPattern> {
        default_patterns()
            .into_iter()
            .filter(|p| matches!(p.category, Category::MemorySafety))
            .collect()
    }

    fn get_crypto_patterns() -> Vec<VulnerabilityPattern> {
        default_patterns()
            .into_iter()
            .filter(|p| matches!(p.category, Category::Cryptography))
            .collect()
    }

    fn get_web_patterns() -> Vec<VulnerabilityPattern> {
        default_patterns()
            .into_iter()
            .filter(|p| {
                matches!(
                    p.category,
                    Category::WebSecurity
                        | Category::AuthenticationAuthorization
                        | Category::InputValidation
                        | Category::CodeInjection
                )
            })
            .collect()
    }

    /// workerd/KJ C++ ruleset: the explicitly-tagged workerd rules plus the
    /// general memory-safety / concurrency patterns.
    fn get_workerd_patterns() -> Vec<VulnerabilityPattern> {
        default_patterns()
            .into_iter()
            .filter(|p| {
                p.ruleset == "workerd"
                    || matches!(p.category, Category::MemorySafety | Category::Concurrency)
            })
            .collect()
    }

    /// The classes the agent campaigns keep producing: broken authorization,
    /// injection, signature verification, replay, resource exhaustion and
    /// checker-soundness bugs. The explicitly tagged autovuln rules plus the
    /// general logic-bug categories.
    fn get_autovuln_patterns() -> Vec<VulnerabilityPattern> {
        default_patterns()
            .into_iter()
            .filter(|p| {
                p.ruleset == "autovuln"
                    || matches!(
                        p.category,
                        Category::AuthenticationAuthorization
                            | Category::CodeInjection
                            | Category::WebSecurity
                            | Category::InputValidation
                            | Category::Cryptography
                    )
            })
            .collect()
    }

    fn get_vuln_patterns() -> Vec<VulnerabilityPattern> {
        default_patterns()
            .into_iter()
            .filter(|p| !matches!(p.category, Category::Generic))
            .collect()
    }
}
