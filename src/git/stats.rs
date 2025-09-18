use super::*;

// Additional statistical analysis functions for Git data

impl RepositoryStats {
    /// Get top contributors by various metrics
    pub fn get_top_contributors(&self, limit: usize) -> Vec<(&String, &AuthorStats)> {
        let mut authors: Vec<_> = self.author_stats.iter().collect();
        authors.sort_by(|a, b| b.1.commits.cmp(&a.1.commits));
        authors.into_iter().take(limit).collect()
    }
}
