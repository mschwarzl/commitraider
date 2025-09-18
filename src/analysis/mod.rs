use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod code_analyzer;
pub mod complexity;
pub mod dependencies;

pub use code_analyzer::CodeAnalyzer;

use crate::config::Config;
use crate::git::RepositoryStats;
use crate::patterns::VulnerabilityFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeStats {
    pub total_lines: usize,
    pub total_files: usize,
    pub language_breakdown: HashMap<String, LanguageStats>,
    pub file_complexity: HashMap<String, ComplexityMetrics>,
    pub dependency_analysis: DependencyAnalysis,
    pub risk_factors: Vec<RiskFactor>,
}

impl Default for CodeStats {
    fn default() -> Self {
        Self {
            total_lines: 0,
            total_files: 0,
            language_breakdown: HashMap::new(),
            file_complexity: HashMap::new(),
            dependency_analysis: DependencyAnalysis::default(),
            risk_factors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageStats {
    pub name: String,
    pub files: usize,
    pub lines: usize,
    pub blank_lines: usize,
    pub comment_lines: usize,
    pub complexity_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityMetrics {
    pub cyclomatic_complexity: f64,
    pub cognitive_complexity: f64,
    pub nesting_depth: usize,
    pub function_count: usize,
    pub line_count: usize,
    pub maintainability_index: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAnalysis {
    pub total_dependencies: usize,
    pub outdated_dependencies: Vec<OutdatedDependency>,
    pub vulnerable_dependencies: Vec<VulnerableDependency>,
    pub license_issues: Vec<LicenseIssue>,
}

impl Default for DependencyAnalysis {
    fn default() -> Self {
        Self {
            total_dependencies: 0,
            outdated_dependencies: Vec::new(),
            vulnerable_dependencies: Vec::new(),
            license_issues: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutdatedDependency {
    pub name: String,
    pub current_version: String,
    pub latest_version: String,
    pub age_days: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableDependency {
    pub name: String,
    pub version: String,
    pub vulnerabilities: Vec<String>, // CVE IDs
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseIssue {
    pub dependency: String,
    pub license: String,
    pub issue_type: String, // "restrictive", "unknown", "conflicting"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskType,
    pub severity: RiskSeverity,
    pub description: String,
    pub affected_files: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskType {
    SingleAuthorFile,
    StaleCode,
    HighComplexity,
    LargeFunctions,
    DeepNesting,
    NoTests,
    OutdatedDependencies,
    VulnerableDependencies,
    LicenseIssues,
    DeadCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedFindings {
    pub git_stats: RepositoryStats,
    pub code_stats: CodeStats,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
    pub config: Config,
}

impl CombinedFindings {
    /// Calculate overall repository risk score
    pub fn calculate_overall_risk(&self) -> f64 {
        let mut risk_score = 0.0;

        // Git-based risks
        risk_score += self.calculate_git_risks();

        // Code-based risks
        risk_score += self.calculate_code_risks();

        // Vulnerability-based risks
        risk_score += self.calculate_vulnerability_risks();

        risk_score.min(10.0)
    }

    fn calculate_git_risks(&self) -> f64 {
        let mut score = 0.0;

        // Single author files
        let single_author_ratio =
            self.git_stats.single_author_files.len() as f64 / self.git_stats.total_files as f64;
        score += single_author_ratio * 2.0;

        // Stale files
        let stale_ratio =
            self.git_stats.stale_files.len() as f64 / self.git_stats.total_files as f64;
        score += stale_ratio * 1.5;

        // High churn files
        let churn_ratio =
            self.git_stats.high_churn_files.len() as f64 / self.git_stats.total_files as f64;
        score += churn_ratio * 1.0;

        score
    }

    fn calculate_code_risks(&self) -> f64 {
        let mut score = 0.0;

        // High complexity files
        let high_complexity_count = self
            .code_stats
            .file_complexity
            .values()
            .filter(|c| c.cyclomatic_complexity > 10.0)
            .count() as f64;
        score += (high_complexity_count / self.code_stats.total_files as f64) * 2.0;

        // Outdated dependencies
        score += (self
            .code_stats
            .dependency_analysis
            .outdated_dependencies
            .len() as f64
            * 0.1)
            .min(1.0);

        // Vulnerable dependencies
        score += self
            .code_stats
            .dependency_analysis
            .vulnerable_dependencies
            .len() as f64
            * 0.5;

        score
    }

    fn calculate_vulnerability_risks(&self) -> f64 {
        self.vulnerabilities
            .iter()
            .map(|v| v.risk_score / 10.0) // Normalize to 0-1 scale
            .sum::<f64>()
            .min(5.0) // Cap at 5 points
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityArea {
    pub area_type: String,
    pub risk_level: RiskSeverity,
    pub description: String,
    pub affected_files: Vec<String>,
    pub recommendation: String,
    pub commit_id: Option<String>,
}
