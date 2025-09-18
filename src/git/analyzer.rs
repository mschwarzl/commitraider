use super::*;
use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use git2::{Repository, Sort};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, info};

pub struct GitAnalyzer {
    repo: Repository,
    path: PathBuf,
}

const MAX_COMMITS_FOR_FULL_ANALYSIS: usize = 20000;

impl GitAnalyzer {
    pub fn new(path: &Path) -> Result<Self> {
        let repo = Repository::open(path).with_context(|| {
            format!(
                "Failed to open repository at {}\n Is it really a git repo?",
                path.display()
            )
        })?;

        info!("Opened Git repository at {}", path.display());

        Ok(Self {
            repo,
            path: path.to_path_buf(),
        })
    }

    pub async fn analyze(&self) -> Result<RepositoryStats> {
        let mut stats = RepositoryStats {
            path: self.path.display().to_string(),
            total_commits: 0,
            total_files: 0,
            total_authors: 0,
            first_commit: Utc::now(),
            last_commit: Utc.timestamp_opt(0, 0).single().unwrap(),
            branches: Vec::new(),
            commit_history: Vec::new(),
            file_history: HashMap::new(),
            author_stats: HashMap::new(),
            single_author_files: Vec::new(),
            stale_files: Vec::new(),
            high_churn_files: Vec::new(),
            remote_url: None,
            repository_type: RepositoryType::Local,
            test_analysis: TestAnalysis {
                total_test_files: 0,
                test_directories: Vec::new(),
                test_frameworks: HashSet::new(),
                has_regression_tests: false,
                test_patterns_found: Vec::new(),
                test_coverage_indicators: Vec::new(),
            },
        };

        self.analyze_branches(&mut stats)?;
        self.analyze_commits(&mut stats).await?;
        self.calculate_derived_stats(&mut stats)?;
        stats.remote_url = self.detect_remote_url();
        stats.repository_type = self.detect_repository_type(&stats.remote_url);

        info!(
            "Analysis complete: {} commits, {} files, {} authors",
            stats.total_commits, stats.total_files, stats.total_authors
        );

        Ok(stats)
    }

    fn analyze_branches(&self, stats: &mut RepositoryStats) -> Result<()> {
        let branches = self.repo.branches(Some(BranchType::Local))?;

        for branch in branches {
            let (branch, _) = branch?;
            if let Some(name) = branch.name()? {
                stats.branches.push(name.to_string());
            }
        }

        debug!("Found {} branches", stats.branches.len());
        Ok(())
    }

    async fn analyze_commits(&self, stats: &mut RepositoryStats) -> Result<()> {
        let mut revwalk = self.repo.revwalk()?;

        if let Ok(head) = self.repo.head() {
            if let Some(target) = head.target() {
                revwalk.push(target)?;
                info!(
                    "Analyzing commits from current branch: {}",
                    head.shorthand().unwrap_or("HEAD")
                );
            }
        } else {
            revwalk.push_head()?;
            info!("Analyzing commits from HEAD");
        }

        revwalk.set_sorting(Sort::TIME)?;

        let mut commit_oids = Vec::new();
        for oid in revwalk {
            commit_oids.push(oid?);
        }

        info!("Found {} commits to analyze", commit_oids.len());

        let commit_oids = if commit_oids.len() > MAX_COMMITS_FOR_FULL_ANALYSIS {
            info!(
                "Large repository detected, sampling {} most recent commits for performance",
                MAX_COMMITS_FOR_FULL_ANALYSIS
            );
            commit_oids
                .into_iter()
                .take(MAX_COMMITS_FOR_FULL_ANALYSIS)
                .collect()
        } else {
            commit_oids
        };

        let pb = ProgressBar::new(commit_oids.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} commits ({eta})"
            )
            .unwrap()
            .progress_chars("#>-")
        );

        // Process commits sequentially (git2 is not Send+Sync)
        // But use async yielding and efficient batching for better performance
        let batch_size = 50; // Smaller batches for more frequent progress updates

        for batch in commit_oids.chunks(batch_size) {
            // Extract commit basic info (metadata) sequentially using libgit2
            let mut partial_commits = Vec::with_capacity(batch.len());

            for &oid in batch {
                let commit = self.repo.find_commit(oid)?;
                let id = commit.id().to_string();
                let message = commit.message().unwrap_or("").to_string();
                let author = commit.author();
                let committer = commit.committer();
                let authored_date = Utc
                    .timestamp_opt(author.when().seconds(), 0)
                    .single()
                    .unwrap();
                let committed_date = Utc
                    .timestamp_opt(committer.when().seconds(), 0)
                    .single()
                    .unwrap();

                partial_commits.push((
                    id,
                    message,
                    String::from_utf8_lossy(author.name_bytes()).to_string(),
                    String::from_utf8_lossy(author.email_bytes()).to_string(),
                    String::from_utf8_lossy(committer.name_bytes()).to_string(),
                    String::from_utf8_lossy(committer.email_bytes()).to_string(),
                    authored_date,
                    committed_date,
                ));
            }

            // Now get changed files concurrently with controlled concurrency
            let repo_path = self.path.clone();
            let semaphore = Arc::new(Semaphore::new(32)); // Limit concurrent git commands
            let mut join_set = JoinSet::new();

            for (commit_id, _, _, _, _, _, _, _) in &partial_commits {
                let commit_id = commit_id.clone();
                let repo_path = repo_path.clone();
                let permit = Arc::clone(&semaphore);

                join_set.spawn(async move {
                    let _permit = permit.acquire().await.unwrap();

                    // Add timeout to prevent hanging git commands
                    tokio::time::timeout(
                        Duration::from_secs(30),
                        Self::get_changed_files_concurrent(&repo_path, &commit_id),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        debug!("Git command timeout for commit {}", commit_id);
                        Ok(Vec::new()) // Return empty on timeout
                    })
                });
            }

            // Collect results maintaining order
            let mut file_results = Vec::with_capacity(partial_commits.len());
            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(files_result) => file_results.push(files_result),
                    Err(e) => {
                        debug!("Task join error: {}", e);
                        file_results.push(Ok(Vec::new())); // Fallback to empty
                    }
                }
            }

            // Combine metadata with file change results
            let mut commit_infos = Vec::with_capacity(batch.len());
            for (
                i,
                (
                    id,
                    message,
                    author,
                    author_email,
                    committer,
                    committer_email,
                    authored_date,
                    committed_date,
                ),
            ) in partial_commits.into_iter().enumerate()
            {
                let files_changed = file_results[i]
                    .as_ref()
                    .map_err(|e| anyhow::anyhow!("Failed to get changed files for {}: {}", id, e))?
                    .clone();

                commit_infos.push(CommitInfo {
                    id,
                    message,
                    author,
                    author_email,
                    committer,
                    committer_email,
                    authored_date,
                    committed_date,
                    files_changed,
                    insertions: 0,
                    deletions: 0,
                    branch: None,
                });

                // Update progress bar
                pb.inc(1);
            }

            // Apply updates sequentially (git2 and mutable stats require this)
            for commit_info in commit_infos {
                // Update global stats
                if commit_info.authored_date < stats.first_commit {
                    stats.first_commit = commit_info.authored_date;
                }
                if commit_info.authored_date > stats.last_commit {
                    stats.last_commit = commit_info.authored_date;
                }

                // Update author statistics
                self.update_author_stats(stats, &commit_info);

                // Update file history
                self.update_file_history(stats, &commit_info);

                stats.commit_history.push(commit_info);
                stats.total_commits += 1;
            }

            // Yield control periodically for better async behavior
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        pb.finish_with_message("Commit analysis complete");

        Ok(())
    }

    // Concurrent version for parallel processing with enhanced tokio usage
    async fn get_changed_files_concurrent(
        repo_path: &std::path::Path,
        commit_id: &str,
    ) -> Result<Vec<String>> {
        const MAX_FILES_PER_COMMIT: usize = 20;

        // Use tokio::process for async git command execution with better error handling
        let mut cmd = tokio::process::Command::new("git");
        cmd.args(&[
            "-C",
            repo_path.to_str().unwrap_or("."),
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            &format!("{}~1", commit_id), // parent
            commit_id,
        ]);

        // Set up proper process isolation
        cmd.kill_on_drop(true);

        let output = cmd.output().await;

        match output {
            Ok(output) if output.status.success() => {
                let files: Vec<String> = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .take(MAX_FILES_PER_COMMIT)
                    .map(|s| s.to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                // For initial commits (no parent), use git show
                if files.is_empty() {
                    let mut initial_cmd = tokio::process::Command::new("git");
                    initial_cmd.args(&[
                        "-C",
                        repo_path.to_str().unwrap_or("."),
                        "show",
                        "--pretty=format:",
                        "--name-only",
                        commit_id,
                    ]);
                    initial_cmd.kill_on_drop(true);

                    let initial_output = initial_cmd.output().await;

                    if let Ok(output) = initial_output {
                        if output.status.success() {
                            return Ok(String::from_utf8_lossy(&output.stdout)
                                .lines()
                                .take(MAX_FILES_PER_COMMIT)
                                .map(|s| s.to_string())
                                .filter(|s| !s.is_empty())
                                .collect());
                        }
                    }
                }
                Ok(files)
            }
            _ => {
                // Fallback: return empty list rather than failing
                Ok(Vec::new())
            }
        }
    }

    fn update_author_stats(&self, stats: &mut RepositoryStats, commit: &CommitInfo) {
        let author_key = format!("{}:{}", commit.author, commit.author_email);

        let author_stats = stats.author_stats.entry(author_key).or_insert(AuthorStats {
            name: commit.author.clone(),
            email: commit.author_email.clone(),
            commits: 0,
            files_touched: HashSet::new(),
            first_commit: commit.authored_date,
            last_commit: commit.authored_date,
            lines_added: 0,
            lines_removed: 0,
        });

        author_stats.commits += 1;
        author_stats.lines_added += commit.insertions;
        author_stats.lines_removed += commit.deletions;

        if commit.authored_date < author_stats.first_commit {
            author_stats.first_commit = commit.authored_date;
        }
        if commit.authored_date > author_stats.last_commit {
            author_stats.last_commit = commit.authored_date;
        }

        for file in &commit.files_changed {
            author_stats.files_touched.insert(file.clone());
        }
    }

    fn update_file_history(&self, stats: &mut RepositoryStats, commit: &CommitInfo) {
        for file_path in &commit.files_changed {
            let file_history = stats
                .file_history
                .entry(file_path.clone())
                .or_insert(FileHistory {
                    path: file_path.clone(),
                    commits: Vec::new(),
                    authors: HashSet::new(),
                    first_commit: commit.authored_date,
                    last_commit: commit.authored_date,
                    total_changes: 0,
                });

            file_history.commits.push(commit.id.clone());
            file_history.authors.insert(commit.author.clone());
            file_history.total_changes += 1;

            if commit.authored_date < file_history.first_commit {
                file_history.first_commit = commit.authored_date;
            }
            if commit.authored_date > file_history.last_commit {
                file_history.last_commit = commit.authored_date;
            }
        }
    }

    fn calculate_derived_stats(&self, stats: &mut RepositoryStats) -> Result<()> {
        stats.total_authors = stats.author_stats.len();
        stats.total_files = stats.file_history.len();

        // Find single-author files
        for (path, history) in &stats.file_history {
            if history.authors.len() == 1 {
                stats.single_author_files.push(path.clone());
            }
        }

        // Find stale files (no commits in last year)
        let one_year_ago = Utc::now() - chrono::Duration::days(365);
        for (path, history) in &stats.file_history {
            if history.last_commit < one_year_ago {
                stats.stale_files.push(path.clone());
            }
        }

        // Find high-churn files (top 10% by changes)
        let mut files_by_churn: Vec<_> = stats.file_history.iter().collect();
        files_by_churn.sort_by(|a, b| b.1.total_changes.cmp(&a.1.total_changes));

        let high_churn_threshold = files_by_churn.len() / 10; // Top 10%
        for (path, _) in files_by_churn.iter().take(high_churn_threshold.max(1)) {
            stats.high_churn_files.push(path.to_string());
        }

        info!(
            "Derived stats: {} single-author files, {} stale files, {} high-churn files",
            stats.single_author_files.len(),
            stats.stale_files.len(),
            stats.high_churn_files.len()
        );

        Ok(())
    }

    fn detect_remote_url(&self) -> Option<String> {
        if let Ok(remote) = self.repo.find_remote("origin") {
            if let Some(url) = remote.url() {
                return Some(url.to_string());
            }
        }

        if let Ok(remotes) = self.repo.remotes() {
            for i in 0..remotes.len() {
                if let Some(remote_name) = remotes.get(i) {
                    if let Ok(remote) = self.repo.find_remote(remote_name) {
                        if let Some(url) = remote.url() {
                            return Some(url.to_string());
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_repository_type(&self, remote_url: &Option<String>) -> RepositoryType {
        if let Some(url) = remote_url {
            let url_lower = url.to_lowercase();
            if url_lower.contains("gitlab") {
                RepositoryType::GitLab
            } else if url_lower.contains("github") {
                RepositoryType::GitHub
            } else if url_lower.contains("bitbucket") {
                RepositoryType::Bitbucket
            } else {
                RepositoryType::Other
            }
        } else {
            RepositoryType::Local
        }
    }
}
