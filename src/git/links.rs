use super::{RepositoryStats, RepositoryType};
use regex::Regex;

pub struct RepositoryLinker<'a> {
    stats: &'a RepositoryStats,
}

impl<'a> RepositoryLinker<'a> {
    pub fn new(stats: &'a RepositoryStats) -> Self {
        Self { stats }
    }

    pub fn get_commit_url(&self, commit_id: &str) -> Option<String> {
        let base_url = self.get_base_url()?;

        match self.stats.repository_type {
            RepositoryType::GitHub => Some(format!("{}/commit/{}", base_url, commit_id)),
            RepositoryType::GitLab => Some(format!("{}/-/commit/{}", base_url, commit_id)),
            RepositoryType::Bitbucket => Some(format!("{}/commits/{}", base_url, commit_id)),
            _ => None,
        }
    }

    pub fn get_file_url(&self, file_path: &str, commit_id: Option<&str>) -> Option<String> {
        let base_url = self.get_base_url()?;

        match self.stats.repository_type {
            RepositoryType::GitHub => {
                if let Some(commit) = commit_id {
                    Some(format!("{}/blob/{}/{}", base_url, commit, file_path))
                } else {
                    Some(format!("{}/blob/main/{}", base_url, file_path))
                }
            }
            RepositoryType::GitLab => {
                if let Some(commit) = commit_id {
                    Some(format!("{}/-/blob/{}/{}", base_url, commit, file_path))
                } else {
                    Some(format!("{}/-/blob/main/{}", base_url, file_path))
                }
            }
            RepositoryType::Bitbucket => {
                if let Some(commit) = commit_id {
                    Some(format!("{}/src/{}/{}", base_url, commit, file_path))
                } else {
                    Some(format!("{}/src/main/{}", base_url, file_path))
                }
            }
            _ => None,
        }
    }

    pub fn get_diff_url(&self, commit_id: &str) -> Option<String> {
        let base_url = self.get_base_url()?;

        match self.stats.repository_type {
            RepositoryType::GitHub => Some(format!("{}/commit/{}.diff", base_url, commit_id)),
            RepositoryType::GitLab => Some(format!("{}/-/commit/{}.diff", base_url, commit_id)),
            RepositoryType::Bitbucket => Some(format!("{}/commits/{}/raw", base_url, commit_id)),
            _ => None,
        }
    }

    pub fn get_repository_name(&self) -> String {
        match self.stats.repository_type {
            RepositoryType::GitHub => "GitHub",
            RepositoryType::GitLab => "GitLab",
            RepositoryType::Bitbucket => "Bitbucket",
            RepositoryType::Other => "Git Repository",
            RepositoryType::Local => "Local Repository",
        }
        .to_string()
    }

    pub fn get_base_url(&self) -> Option<String> {
        let remote_url = self.stats.remote_url.as_ref()?;

        // Convert SSH URLs to HTTPS URLs
        let url = if remote_url.starts_with("git@") {
            self.convert_ssh_to_https(remote_url)?
        } else {
            remote_url.clone()
        };

        // Remove .git suffix
        let url = if url.ends_with(".git") {
            url[..url.len() - 4].to_string()
        } else {
            url
        };

        Some(url)
    }

    fn convert_ssh_to_https(&self, ssh_url: &str) -> Option<String> {
        // Convert git@hostname:owner/repo.git to https://hostname/owner/repo
        let re = Regex::new(r"git@([^:]+):(.+)").ok()?;

        if let Some(captures) = re.captures(ssh_url) {
            let hostname = captures.get(1)?.as_str();
            let path = captures.get(2)?.as_str();

            // Remove .git suffix from path if present
            let path = if path.ends_with(".git") {
                &path[..path.len() - 4]
            } else {
                path
            };

            Some(format!("https://{}/{}", hostname, path))
        } else {
            None
        }
    }

    pub fn extract_issue_references(&self, text: &str) -> Vec<String> {
        let mut references = Vec::new();

        let patterns = [
            r"#(\d+)",              // #123
            r"issue\s+#?(\d+)",     // issue #123 or issue 123
            r"fixes?\s+#?(\d+)",    // fixes #123
            r"closes?\s+#?(\d+)",   // closes #123
            r"resolves?\s+#?(\d+)", // resolves #123
        ];

        for pattern in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                for capture in re.captures_iter(text) {
                    if let Some(issue_num) = capture.get(1) {
                        let issue_id = issue_num.as_str().to_string();
                        if !references.contains(&issue_id) {
                            references.push(issue_id);
                        }
                    }
                }
            }
        }

        references
    }

    pub fn get_issue_url(&self, issue_number: &str) -> Option<String> {
        let base_url = self.get_base_url()?;

        match self.stats.repository_type {
            RepositoryType::GitHub => Some(format!("{}/issues/{}", base_url, issue_number)),
            RepositoryType::GitLab => Some(format!("{}/-/issues/{}", base_url, issue_number)),
            RepositoryType::Bitbucket => Some(format!("{}/issues/{}", base_url, issue_number)),
            _ => None,
        }
    }
}
