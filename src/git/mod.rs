use chrono::{DateTime, Utc};
use git2::BranchType;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub mod analyzer;
pub mod links;
pub mod stats;

pub use analyzer::GitAnalyzer;
pub use links::RepositoryLinker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitInfo {
    pub id: String,
    pub message: String,
    pub author: String,
    pub author_email: String,
    pub committer: String,
    pub committer_email: String,
    pub authored_date: DateTime<Utc>,
    pub committed_date: DateTime<Utc>,
    pub files_changed: Vec<String>,
    pub insertions: usize,
    pub deletions: usize,
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHistory {
    pub path: String,
    pub commits: Vec<String>,
    pub authors: HashSet<String>,
    pub first_commit: DateTime<Utc>,
    pub last_commit: DateTime<Utc>,
    pub total_changes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorStats {
    pub name: String,
    pub email: String,
    pub commits: usize,
    pub files_touched: HashSet<String>,
    pub first_commit: DateTime<Utc>,
    pub last_commit: DateTime<Utc>,
    pub lines_added: usize,
    pub lines_removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryStats {
    pub path: String,
    pub total_commits: usize,
    pub total_files: usize,
    pub total_authors: usize,
    pub first_commit: DateTime<Utc>,
    pub last_commit: DateTime<Utc>,
    pub branches: Vec<String>,
    pub commit_history: Vec<CommitInfo>,
    pub file_history: HashMap<String, FileHistory>,
    pub author_stats: HashMap<String, AuthorStats>,
    pub single_author_files: Vec<String>,
    pub stale_files: Vec<String>,
    pub high_churn_files: Vec<String>,
    pub remote_url: Option<String>,
    pub repository_type: RepositoryType,
    pub test_analysis: TestAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepositoryType {
    GitHub,
    GitLab,
    Bitbucket,
    Other,
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAnalysis {
    pub total_test_files: usize,
    pub test_directories: Vec<String>,
    pub test_frameworks: HashSet<String>,
    pub has_regression_tests: bool,
    pub test_patterns_found: Vec<String>,
    pub test_coverage_indicators: Vec<String>,
}
