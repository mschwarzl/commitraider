use super::*;
use crate::git::RepositoryStats;
use anyhow::{Context, Result};
use fancy_regex::Regex;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::path::Path;
use tracing::info;

pub struct PatternEngine {
    compiled_patterns: Vec<(Regex, VulnerabilityPattern)>,
}

impl PatternEngine {
    pub fn new(pattern_set: &str) -> Result<Self> {
        let patterns = match pattern_set {
            "memorysafety" => Self::get_memory_safety_patterns(),
            "crypto" => Self::get_crypto_patterns(),
            "web" => Self::get_web_patterns(),
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
        info!("Entering scan_repository method");

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
        info!("Found {} potential vulnerabilities", findings.len());
        Ok(findings)
    }

    fn analyze_commit(
        &self,
        commit: &crate::git::CommitInfo,
    ) -> Result<Option<VulnerabilityFinding>> {
        let mut patterns_matched = Vec::new();
        let mut cve_references = Vec::new();

        // Go through commit message and match the compiled patterns
        for (regex, pattern) in &self.compiled_patterns {
            if let Ok(Some(captures)) = regex.captures(&commit.message) {
                let matched_text = captures.get(0).unwrap().as_str().to_string();
                if pattern.name == "CVE Reference" {
                    if let Ok(Some(cve_match)) = regex.captures(&commit.message) {
                        if let Some(cve_id) = cve_match.get(1) {
                            cve_references.push(format!("CVE-{}", cve_id.as_str()));
                        }
                    }
                }
                patterns_matched.push(PatternMatch {
                    pattern_name: pattern.name.clone(),
                    matched_text,
                    severity: pattern.severity.clone(),
                    category: pattern.category.clone(),
                    file_path: "commit_message".to_string(),
                    line_number: None,
                    context: commit.message.clone(),
                    cve_references: cve_references.clone(),
                });
            }
        }

        if patterns_matched.is_empty() {
            return Ok(None);
        }

        let risk_score = self.calculate_risk_score(&patterns_matched, commit);

        Ok(Some(VulnerabilityFinding {
            commit_id: commit.id.clone(),
            commit_message: commit.message.clone(),
            author: commit.author.clone(),
            date: commit.authored_date,
            files_changed: commit.files_changed.clone(),
            patterns_matched,
            risk_score,
            cve_references,
        }))
    }

    fn calculate_risk_score(
        &self,
        patterns: &[PatternMatch],
        commit: &crate::git::CommitInfo,
    ) -> f64 {
        let base_score: f64 = patterns
            .iter()
            .map(|p| match p.severity {
                Severity::Critical => 9.0,
                Severity::High => 7.0,
                Severity::Medium => 5.0,
                Severity::Low => 3.0,
                Severity::Info => 1.0,
            })
            .sum();

        let file_multiplier = (commit.files_changed.len() as f64).sqrt();
        let cve_multiplier = if patterns.iter().any(|p| p.pattern_name == "CVE Reference") {
            2.0
        } else {
            1.0
        };

        (base_score * file_multiplier * cve_multiplier).min(10.0)
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
            .filter(|p| matches!(p.category, Category::WebSecurity))
            .collect()
    }

    fn get_vuln_patterns() -> Vec<VulnerabilityPattern> {
        default_patterns()
            .into_iter()
            .filter(|p| !matches!(p.category, Category::Generic))
            .collect()
    }
}
