use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::analysis::CombinedFindings;
use crate::patterns::{Category, Severity};

/// Schema version for the agent report format
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Schema URL for validation (placeholder - replace with actual URL if published)
pub const SCHEMA_URL: &str = "<placeholder>/v1/agent-report.json";

/// JSON Schema document for the agent report format
pub const JSON_SCHEMA: &str = r#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "<placeholder>/v1/agent-report.json",
  "title": "CommitRaider Agent Report",
  "description": "Compact security analysis report for agent consumption",
  "type": "object",
  "required": ["$schema", "version", "generated_at", "repository", "summary", "findings", "risk_files", "dependencies"],
  "properties": {
    "$schema": {
      "type": "string",
      "description": "Schema URL for validation"
    },
    "version": {
      "type": "string",
      "description": "Schema version"
    },
    "generated_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp when the report was generated"
    },
    "repository": {
      "type": "object",
      "required": ["path", "repository_type", "total_commits", "total_files", "total_authors", "first_commit", "last_commit", "branches"],
      "properties": {
        "path": { "type": "string" },
        "repository_type": { "type": "string", "enum": ["GitHub", "GitLab", "Bitbucket", "Other", "Local"] },
        "total_commits": { "type": "integer", "minimum": 0 },
        "total_files": { "type": "integer", "minimum": 0 },
        "total_authors": { "type": "integer", "minimum": 0 },
        "first_commit": { "type": "string", "format": "date-time" },
        "last_commit": { "type": "string", "format": "date-time" },
        "branches": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "summary": {
      "type": "object",
      "required": ["overall_risk_score", "critical_findings", "high_findings", "medium_findings", "low_findings", "info_findings", "total_findings", "cve_count", "unique_cves", "single_author_file_count", "stale_file_count", "high_churn_file_count"],
      "properties": {
        "overall_risk_score": { "type": "number", "minimum": 0, "maximum": 10 },
        "critical_findings": { "type": "integer", "minimum": 0 },
        "high_findings": { "type": "integer", "minimum": 0 },
        "medium_findings": { "type": "integer", "minimum": 0 },
        "low_findings": { "type": "integer", "minimum": 0 },
        "info_findings": { "type": "integer", "minimum": 0 },
        "total_findings": { "type": "integer", "minimum": 0 },
        "cve_count": { "type": "integer", "minimum": 0 },
        "unique_cves": {
          "type": "array",
          "items": { "type": "string" }
        },
        "single_author_file_count": { "type": "integer", "minimum": 0 },
        "stale_file_count": { "type": "integer", "minimum": 0 },
        "high_churn_file_count": { "type": "integer", "minimum": 0 }
      }
    },
    "findings": {
      "type": "array",
      "description": "Vulnerability findings sorted by risk score (limited by --top-n)",
      "items": {
        "type": "object",
        "required": ["commit_id", "commit_message", "author", "date", "risk_score", "severity", "patterns", "cves", "files_changed"],
        "properties": {
          "commit_id": { "type": "string" },
          "commit_message": { "type": "string" },
          "author": { "type": "string" },
          "date": { "type": "string", "format": "date-time" },
          "risk_score": { "type": "number", "minimum": 0, "maximum": 10 },
          "severity": { "type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"] },
          "patterns": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["name", "severity", "category", "matched_text"],
              "properties": {
                "name": { "type": "string" },
                "severity": { "type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"] },
                "category": { "type": "string", "enum": ["MemorySafety", "Cryptography", "WebSecurity", "InputValidation", "AuthenticationAuthorization", "Concurrency", "DataExposure", "CodeInjection", "Generic"] },
                "cwe": { "type": ["string", "null"] },
                "matched_text": { "type": "string" }
              }
            }
          },
          "cves": {
            "type": "array",
            "items": { "type": "string" }
          },
          "files_changed": {
            "type": "array",
            "items": { "type": "string" }
          }
        }
      }
    },
    "risk_files": {
      "type": "array",
      "description": "High-risk files identified by ownership, staleness, or complexity",
      "items": {
        "type": "object",
        "required": ["path", "risk_factors", "single_author", "stale", "high_churn", "author_count"],
        "properties": {
          "path": { "type": "string" },
          "risk_factors": {
            "type": "array",
            "items": { "type": "string" }
          },
          "single_author": { "type": "boolean" },
          "stale": { "type": "boolean" },
          "high_churn": { "type": "boolean" },
          "days_since_last_commit": { "type": ["integer", "null"], "minimum": 0 },
          "author_count": { "type": "integer", "minimum": 0 },
          "complexity": {
            "type": ["object", "null"],
            "required": ["cyclomatic_complexity", "cognitive_complexity", "nesting_depth", "function_count", "line_count", "maintainability_index"],
            "properties": {
              "cyclomatic_complexity": { "type": "number" },
              "cognitive_complexity": { "type": "number" },
              "nesting_depth": { "type": "integer" },
              "function_count": { "type": "integer" },
              "line_count": { "type": "integer" },
              "maintainability_index": { "type": "number" }
            }
          }
        }
      }
    },
    "dependencies": {
      "type": "object",
      "required": ["total_dependencies", "outdated_count", "vulnerable_count", "license_issue_count", "vulnerable_packages"],
      "properties": {
        "total_dependencies": { "type": "integer", "minimum": 0 },
        "outdated_count": { "type": "integer", "minimum": 0 },
        "vulnerable_count": { "type": "integer", "minimum": 0 },
        "license_issue_count": { "type": "integer", "minimum": 0 },
        "vulnerable_packages": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["name", "version", "vulnerabilities", "severity"],
            "properties": {
              "name": { "type": "string" },
              "version": { "type": "string" },
              "vulnerabilities": {
                "type": "array",
                "items": { "type": "string" }
              },
              "severity": { "type": "string" }
            }
          }
        }
      }
    }
  }
}"#;

/// Compact, agent-friendly report format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReport {
    /// Schema metadata
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub generated_at: DateTime<Utc>,

    /// Repository overview
    pub repository: RepositorySummary,

    /// High-level summary for quick assessment
    pub summary: ReportSummary,

    /// Vulnerability findings (sorted by risk score, limited by --top-n)
    pub findings: Vec<AgentFinding>,

    /// High-risk files (complexity, ownership, staleness issues)
    pub risk_files: Vec<RiskFile>,

    /// Dependency security issues
    pub dependencies: DependencyIssues,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositorySummary {
    pub path: String,
    pub repository_type: String,
    pub total_commits: usize,
    pub total_files: usize,
    pub total_authors: usize,
    pub first_commit: DateTime<Utc>,
    pub last_commit: DateTime<Utc>,
    pub branches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub overall_risk_score: f64,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub info_findings: usize,
    pub total_findings: usize,
    pub cve_count: usize,
    pub unique_cves: Vec<String>,
    pub single_author_file_count: usize,
    pub stale_file_count: usize,
    pub high_churn_file_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFinding {
    pub commit_id: String,
    pub commit_message: String,
    pub author: String,
    pub date: DateTime<Utc>,
    pub risk_score: f64,
    pub severity: Severity,
    pub patterns: Vec<PatternMatchSummary>,
    pub cves: Vec<String>,
    pub files_changed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatchSummary {
    pub name: String,
    pub severity: Severity,
    pub category: Category,
    pub cwe: Option<String>,
    pub matched_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFile {
    pub path: String,
    pub risk_factors: Vec<String>,
    pub single_author: bool,
    pub stale: bool,
    pub high_churn: bool,
    pub days_since_last_commit: Option<u64>,
    pub author_count: usize,
    pub complexity: Option<FileComplexitySummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileComplexitySummary {
    pub cyclomatic_complexity: f64,
    pub cognitive_complexity: f64,
    pub nesting_depth: usize,
    pub function_count: usize,
    pub line_count: usize,
    pub maintainability_index: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyIssues {
    pub total_dependencies: usize,
    pub outdated_count: usize,
    pub vulnerable_count: usize,
    pub license_issue_count: usize,
    pub vulnerable_packages: Vec<VulnerablePackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerablePackage {
    pub name: String,
    pub version: String,
    pub vulnerabilities: Vec<String>,
    pub severity: String,
}

// Compact structs for ultra-small output
// Balanced approach: compact field names but keeps essential vulnerability info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactAgentReport {
    /// Version
    pub v: String,
    /// Repository path
    pub repo: String,
    /// Overall risk score (0-10)
    pub risk: f64,
    /// Summary counts by severity
    pub counts: SeverityCounts,
    /// Total findings
    pub total: usize,
    /// Unique CVEs found
    pub cves: Vec<String>,
    /// Top vulnerability findings (up to 15)
    pub vulns: Vec<CompactVulnerability>,
    /// Top risk files (up to 10)
    pub files: Vec<CompactRiskFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub crit: usize,
    pub high: usize,
    pub med: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactVulnerability {
    /// Commit ID (shortened to 8 chars)
    pub id: String,
    /// Commit message (truncated to 120 chars)
    pub msg: String,
    /// Risk score (0-10)
    pub score: f64,
    /// Severity level
    pub sev: String,
    /// Patterns matched
    pub pat: Vec<CompactPattern>,
    /// CVE references
    pub cve: Vec<String>,
    /// Files changed (just basenames)
    pub files: Vec<String>,
    /// Backport count: how many branches shipped this same fix (>1 = strong CVE signal)
    #[serde(default = "default_bp")]
    pub bp: usize,
    /// Changed-lines diff snippet (source files only, capped) for triage
    #[serde(default)]
    pub diff: String,
}

fn default_bp() -> usize {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactPattern {
    /// Pattern name
    pub n: String,
    /// Severity
    pub s: String,
    /// Category
    pub c: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactRiskFile {
    /// File path
    pub p: String,
    /// Risk factors
    pub f: Vec<String>,
}

impl CompactAgentReport {
    pub fn from_combined_findings(findings: &CombinedFindings) -> Self {
        let summary = AgentReport::calculate_summary(findings);
        let vulns = Self::extract_compact_vulns(findings, 15);
        let risk_files = Self::extract_compact_risk_files(findings, 10);

        // Use only the basename to avoid leaking absolute filesystem paths
        let repo_name = std::path::Path::new(&findings.git_stats.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&findings.git_stats.path)
            .to_string();

        Self {
            v: "1.0.0".to_string(),
            repo: repo_name,
            risk: summary.overall_risk_score,
            counts: SeverityCounts {
                crit: summary.critical_findings,
                high: summary.high_findings,
                med: summary.medium_findings,
                low: summary.low_findings,
                info: summary.info_findings,
            },
            total: summary.total_findings,
            cves: summary.unique_cves,
            vulns,
            files: risk_files,
        }
    }

    fn extract_compact_vulns(
        findings: &CombinedFindings,
        top_n: usize,
    ) -> Vec<CompactVulnerability> {
        let mut sorted: Vec<_> = findings.vulnerabilities.clone();
        sorted.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());

        sorted
            .into_iter()
            .take(top_n)
            .map(|v| CompactVulnerability {
                id: v.commit_id.chars().take(8).collect(),
                msg: Self::truncate(&v.commit_message, 120),
                score: v.risk_score,
                sev: format!("{:?}", Self::get_max_severity(&v.patterns_matched)),
                pat: v
                    .patterns_matched
                    .into_iter()
                    .map(|p| CompactPattern {
                        n: p.pattern_name,
                        s: format!("{:?}", p.severity),
                        c: format!("{:?}", p.category),
                    })
                    .collect(),
                cve: v.cve_references,
                files: v
                    .files_changed
                    .into_iter()
                    .map(|f| {
                        std::path::Path::new(&f)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(&f)
                            .to_string()
                    })
                    .collect(),
                bp: v.backport_count,
                diff: v.diff_snippet,
            })
            .collect()
    }

    fn extract_compact_risk_files(
        findings: &CombinedFindings,
        top_n: usize,
    ) -> Vec<CompactRiskFile> {
        let risk_files = AgentReport::extract_risk_files(findings, top_n);
        risk_files
            .into_iter()
            .map(|f| CompactRiskFile {
                p: f.path,
                f: f.risk_factors,
            })
            .collect()
    }

    fn truncate(s: &str, max_len: usize) -> String {
        // Use char-based truncation to avoid panicking on multi-byte UTF-8 characters
        let char_count = s.chars().count();
        if char_count <= max_len {
            s.to_string()
        } else {
            let truncated: String = s.chars().take(max_len).collect();
            format!("{}...", truncated)
        }
    }

    fn get_max_severity(patterns: &[crate::patterns::PatternMatch]) -> crate::patterns::Severity {
        use crate::patterns::Severity;
        patterns
            .iter()
            .map(|p| &p.severity)
            .max_by_key(|s| match s {
                Severity::Critical => 5,
                Severity::High => 4,
                Severity::Medium => 3,
                Severity::Low => 2,
                Severity::Info => 1,
            })
            .cloned()
            .unwrap_or(Severity::Info)
    }

    pub fn generate_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

impl AgentReport {
    pub fn from_combined_findings(findings: &CombinedFindings, top_n: usize) -> Self {
        let now = Utc::now();

        Self {
            schema: SCHEMA_URL.to_string(),
            version: SCHEMA_VERSION.to_string(),
            generated_at: now,
            repository: Self::extract_repository_summary(&findings.git_stats),
            summary: Self::calculate_summary(findings),
            findings: Self::extract_findings(findings, top_n),
            risk_files: Self::extract_risk_files(findings, top_n),
            dependencies: Self::extract_dependencies(&findings.code_stats.dependency_analysis),
        }
    }

    fn extract_repository_summary(git_stats: &crate::git::RepositoryStats) -> RepositorySummary {
        // Use only the basename to avoid leaking absolute filesystem paths
        let repo_name = std::path::Path::new(&git_stats.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&git_stats.path)
            .to_string();

        RepositorySummary {
            path: repo_name,
            repository_type: format!("{:?}", git_stats.repository_type),
            total_commits: git_stats.total_commits,
            total_files: git_stats.total_files,
            total_authors: git_stats.total_authors,
            first_commit: git_stats.first_commit,
            last_commit: git_stats.last_commit,
            branches: git_stats.branches.clone(),
        }
    }

    fn calculate_summary(findings: &CombinedFindings) -> ReportSummary {
        let mut critical = 0usize;
        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        let mut info = 0usize;
        let mut all_cves: std::collections::HashSet<String> = std::collections::HashSet::new();

        for finding in &findings.vulnerabilities {
            // Canonical severity, shared with the HTML report. See
            // VulnerabilityFinding::severity.
            match finding.severity() {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info += 1,
            }

            // Collect CVEs
            for cve in &finding.cve_references {
                all_cves.insert(cve.clone());
            }
        }

        let overall_risk = findings.calculate_overall_risk();
        let unique_cves: Vec<String> = all_cves.into_iter().collect();

        ReportSummary {
            overall_risk_score: overall_risk,
            critical_findings: critical,
            high_findings: high,
            medium_findings: medium,
            low_findings: low,
            info_findings: info,
            total_findings: findings.vulnerabilities.len(),
            cve_count: unique_cves.len(),
            unique_cves,
            single_author_file_count: findings.git_stats.single_author_files.len(),
            stale_file_count: findings.git_stats.stale_files.len(),
            high_churn_file_count: findings.git_stats.high_churn_files.len(),
        }
    }

    fn extract_findings(findings: &CombinedFindings, top_n: usize) -> Vec<AgentFinding> {
        let mut sorted_findings: Vec<_> = findings.vulnerabilities.clone();
        sorted_findings.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());

        sorted_findings
            .into_iter()
            .take(top_n)
            .map(|v| {
                // Compute before the struct partially moves out of `v`.
                let severity = v.severity();
                AgentFinding {
                    commit_id: v.commit_id,
                    commit_message: v.commit_message,
                    author: v.author,
                    date: v.date,
                    risk_score: v.risk_score,
                    severity,
                    patterns: v
                        .patterns_matched
                        .into_iter()
                        .map(|p| PatternMatchSummary {
                            name: p.pattern_name,
                            severity: p.severity,
                            category: p.category,
                            cwe: None, // Could extract from pattern definition if needed
                            matched_text: p.matched_text,
                        })
                        .collect(),
                    cves: v.cve_references,
                    files_changed: v.files_changed,
                }
            })
            .collect()
    }

    fn extract_risk_files(findings: &CombinedFindings, top_n: usize) -> Vec<RiskFile> {
        let mut risk_files: Vec<RiskFile> = Vec::new();
        let now = Utc::now();

        // Process each file in file_history
        for (path, file_history) in &findings.git_stats.file_history {
            let mut risk_factors = Vec::new();
            let is_single_author = file_history.authors.len() == 1;
            let days_since_commit = (now - file_history.last_commit).num_days() as u64;
            let is_stale = days_since_commit > 365; // Use config default
            let is_high_churn = file_history.total_changes > 50; // Threshold

            if is_single_author {
                risk_factors.push("single_author".to_string());
            }
            if is_stale {
                risk_factors.push("stale".to_string());
            }
            if is_high_churn {
                risk_factors.push("high_churn".to_string());
            }

            // Check complexity if available
            let complexity =
                findings
                    .code_stats
                    .file_complexity
                    .get(path)
                    .map(|c| FileComplexitySummary {
                        cyclomatic_complexity: c.cyclomatic_complexity,
                        cognitive_complexity: c.cognitive_complexity,
                        nesting_depth: c.nesting_depth,
                        function_count: c.function_count,
                        line_count: c.line_count,
                        maintainability_index: c.maintainability_index,
                    });

            if complexity
                .as_ref()
                .map(|c| c.cyclomatic_complexity > 10.0)
                .unwrap_or(false)
            {
                risk_factors.push("high_complexity".to_string());
            }

            // Only include files with risk factors
            if !risk_factors.is_empty() {
                risk_files.push(RiskFile {
                    path: path.clone(),
                    risk_factors,
                    single_author: is_single_author,
                    stale: is_stale,
                    high_churn: is_high_churn,
                    days_since_last_commit: Some(days_since_commit),
                    author_count: file_history.authors.len(),
                    complexity,
                });
            }
        }

        // Sort by risk (priority: stale > single_author > high_churn > complexity)
        risk_files.sort_by(|a, b| {
            let a_score = (if a.stale { 100 } else { 0 })
                + (if a.single_author { 50 } else { 0 })
                + (if a.high_churn { 25 } else { 0 })
                + a.complexity
                    .as_ref()
                    .map(|c| c.cyclomatic_complexity as usize)
                    .unwrap_or(0);
            let b_score = (if b.stale { 100 } else { 0 })
                + (if b.single_author { 50 } else { 0 })
                + (if b.high_churn { 25 } else { 0 })
                + b.complexity
                    .as_ref()
                    .map(|c| c.cyclomatic_complexity as usize)
                    .unwrap_or(0);
            b_score.cmp(&a_score)
        });

        risk_files.into_iter().take(top_n).collect()
    }

    fn extract_dependencies(deps: &crate::analysis::DependencyAnalysis) -> DependencyIssues {
        DependencyIssues {
            total_dependencies: deps.total_dependencies,
            outdated_count: deps.outdated_dependencies.len(),
            vulnerable_count: deps.vulnerable_dependencies.len(),
            license_issue_count: deps.license_issues.len(),
            vulnerable_packages: deps
                .vulnerable_dependencies
                .iter()
                .map(|v| VulnerablePackage {
                    name: v.name.clone(),
                    version: v.version.clone(),
                    vulnerabilities: v.vulnerabilities.clone(),
                    severity: v.severity.clone(),
                })
                .collect(),
        }
    }

    /// Generate compact JSON output (minified)
    pub fn generate_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Generate pretty-printed JSON for debugging
    #[allow(dead_code)] // debugging helper, kept for ad-hoc use
    pub fn generate_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Output the JSON schema for the agent report format
    pub fn print_schema() {
        println!("{}", JSON_SCHEMA);
    }
}
