use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub patterns: PatternConfig,
    pub analysis: AnalysisConfig,
    pub output: OutputConfig,
    pub risk: RiskConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternConfig {
    pub custom_patterns: Vec<CustomPattern>,
    pub enabled_categories: Vec<String>,
    pub severity_weights: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub category: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub max_commits: Option<usize>,
    pub include_merge_commits: bool,
    pub stale_threshold_days: u64,
    pub complexity_threshold: f64,
    pub parallel_processing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub default_format: String,
    pub include_stats: bool,
    pub max_items_per_section: usize,
    pub color_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskConfig {
    pub single_author_weight: f64,
    pub stale_file_weight: f64,
    pub complexity_weight: f64,
    pub vulnerability_weight: f64,
}

impl Default for Config {
    fn default() -> Self {
        let mut severity_weights = HashMap::new();
        severity_weights.insert("critical".to_string(), 9.0);
        severity_weights.insert("high".to_string(), 7.0);
        severity_weights.insert("medium".to_string(), 5.0);
        severity_weights.insert("low".to_string(), 3.0);
        severity_weights.insert("info".to_string(), 1.0);

        Self {
            patterns: PatternConfig {
                custom_patterns: Vec::new(),
                enabled_categories: vec![
                    "MemorySafety".to_string(),
                    "WebSecurity".to_string(),
                    "Cryptography".to_string(),
                    "CodeInjection".to_string(),
                ],
                severity_weights,
            },
            analysis: AnalysisConfig {
                max_commits: None,
                include_merge_commits: false,
                stale_threshold_days: 365,
                complexity_threshold: 10.0,
                parallel_processing: true,
            },
            output: OutputConfig {
                default_format: "html".to_string(),
                include_stats: true,
                max_items_per_section: 50,
                color_output: true,
            },
            risk: RiskConfig {
                single_author_weight: 2.0,
                stale_file_weight: 1.5,
                complexity_weight: 2.0,
                vulnerability_weight: 3.0,
            },
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        // Load config from yaml/toml whatever file
        Ok(Self::default())
    }
}
