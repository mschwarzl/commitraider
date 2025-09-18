use super::*;
use super::complexity::ComplexityCalculator;
use anyhow::Result;
use ignore::Walk;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use tokei::{Config as TokeiConfig, Languages};
use tracing::{debug, info};

pub struct CodeAnalyzer;

impl CodeAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub async fn analyze(&self, repo_path: &Path, stale_days: u64) -> Result<CodeStats> {
        // Use tokei for language analysis
        debug!("Starting tokei language analysis...");
        let mut languages = Languages::new();
        let tokei_config = TokeiConfig::default();

        languages.get_statistics(&[repo_path], &[], &tokei_config);
        debug!("Tokei analysis complete");

        let language_breakdown = self.extract_language_stats(&languages);
        let total_lines = language_breakdown.values().map(|l| l.lines).sum();
        let total_files = language_breakdown.values().map(|l| l.files).sum();

        debug!("Starting file complexity analysis...");
        // Analyze file complexity
        let file_complexity = self.analyze_file_complexity(repo_path).await?;
        debug!("File complexity analysis complete");

        // Analyze dependencies
        let dependency_analysis = self.analyze_dependencies(repo_path).await?;
        let risk_factors = self
            .calculate_risk_factors(repo_path, &file_complexity, stale_days)
            .await?;

        info!(
            "Code analysis complete: {} lines across {} files in {} languages",
            total_lines,
            total_files,
            language_breakdown.len()
        );

        Ok(CodeStats {
            total_lines,
            total_files,
            language_breakdown,
            file_complexity,
            dependency_analysis,
            risk_factors,
        })
    }

    fn extract_language_stats(&self, languages: &Languages) -> HashMap<String, LanguageStats> {
        let mut stats = HashMap::new();

        for (lang_type, lang) in languages.iter() {
            let name = format!("{:?}", lang_type);

            stats.insert(
                name.clone(),
                LanguageStats {
                    name,
                    files: lang.reports.len(),
                    lines: lang.lines(),
                    blank_lines: lang.blanks,
                    comment_lines: lang.comments,
                    complexity_score: 0.0, // TODO: Calculate based on language characteristics
                },
            );
        }

        stats
    }

    async fn analyze_file_complexity(
        &self,
        repo_path: &Path,
    ) -> Result<HashMap<String, ComplexityMetrics>> {
        let mut complexity_map = HashMap::new();

        // First pass: collect all files to analyze
        debug!("Collecting files for complexity analysis...");
        let mut files_to_analyze = Vec::new();

        for entry in Walk::new(repo_path) {
            let entry = entry?;
            if entry.file_type().map_or(false, |ft| ft.is_file()) {
                let path = entry.path();
                if let Some(extension) = path.extension() {
                    if self.should_analyze_file(extension.to_string_lossy().as_ref()) {
                        let relative_path = path
                            .strip_prefix(repo_path)
                            .unwrap_or(path)
                            .display()
                            .to_string();
                        files_to_analyze.push((path.to_path_buf(), relative_path));
                    }
                }
            }
        }

        info!(
            "Found {} files to analyze for complexity",
            files_to_analyze.len()
        );

        if files_to_analyze.is_empty() {
            return Ok(complexity_map);
        }

        // Create progress bar
        let pb = ProgressBar::new(files_to_analyze.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} files ({eta})"
            )
            .unwrap()
            .progress_chars("#>-")
        );

        // Second pass: analyze files with progress bar
        for (path, relative_path) in files_to_analyze {
            let metrics = self.calculate_simple_complexity(&path).await?;
            complexity_map.insert(relative_path, metrics);

            pb.inc(1);

            // Yield control periodically for async
            tokio::task::yield_now().await;
        }

        pb.finish_with_message("File complexity analysis complete");
        Ok(complexity_map)
    }

    async fn calculate_simple_complexity(&self, file_path: &Path) -> Result<ComplexityMetrics> {
        let calculator = ComplexityCalculator::new();
        // Skip binary files
        if self.is_binary_file(file_path).await? {
            return Ok(ComplexityMetrics {
                function_count: 0,
                nesting_depth: 0,
                cyclomatic_complexity: 0.0,
                cognitive_complexity: 0.0,
                line_count: 0,
                maintainability_index: 0.0,
            });
        }

        let content = match tokio::fs::read_to_string(file_path).await {
            Ok(content) => content,
            Err(_) => {
                // Skip files with invalid UTF-8
                return Ok(ComplexityMetrics {
                    function_count: 0,
                    nesting_depth: 0,
                    cyclomatic_complexity: 0.0,
                    cognitive_complexity: 0.0,
                    line_count: 0,
                    maintainability_index: 0.0,
                });
            }
        };
        let lines: Vec<&str> = content.lines().collect();

        // Use the complexity calculator
        calculator.calculate_complexity_metrics(&lines, file_path)
    }

    async fn is_binary_file(&self, file_path: &Path) -> Result<bool> {
        // Check file extension first
        if let Some(extension) = file_path.extension() {
            if let Some(ext_str) = extension.to_str() {
                let binary_extensions = [
                    "exe", "dll", "so", "dylib", "bin", "o", "obj", "lib", "a", "zip", "tar", "gz",
                    "bz2", "xz", "7z", "rar", "jpg", "jpeg", "png", "gif", "bmp", "ico", "tiff",
                    "mp3", "mp4", "avi", "mov", "wav", "pdf", "doc", "docx",
                ];
                if binary_extensions.contains(&ext_str.to_lowercase().as_str()) {
                    return Ok(true);
                }
            }
        }

        // Read first few bytes to check for null bytes (binary indicator)
        match tokio::fs::read(file_path).await {
            Ok(bytes) => {
                if bytes.len() > 0 {
                    // Check first 1024 bytes for null bytes
                    let check_len = std::cmp::min(1024, bytes.len());
                    let contains_null = bytes[..check_len].iter().any(|&b| b == 0);
                    Ok(contains_null)
                } else {
                    Ok(false) // Empty files are not binary
                }
            }
            Err(_) => Ok(false), // If we can't read it, assume it's not binary
        }
    }

    fn should_analyze_file(&self, extension: &str) -> bool {
        matches!(
            extension,
            "rs" | "py"
                | "js"
                | "ts"
                | "java"
                | "cpp"
                | "c"
                | "h"
                | "hpp"
                | "go"
                | "rb"
                | "php"
                | "cs"
        )
    }

    async fn analyze_dependencies(&self, repo_path: &Path) -> Result<DependencyAnalysis> {
        let mut total_dependencies = 0;
        let outdated_dependencies = Vec::new();
        let vulnerable_dependencies = Vec::new();
        let license_issues = Vec::new();

        // Check for different dependency files
        let dependency_files = [
            "Cargo.toml",
            "package.json",
            "requirements.txt",
            "pom.xml",
            "build.gradle",
            "go.mod",
            "Gemfile",
        ];

        for dep_file in dependency_files {
            let dep_path = repo_path.join(dep_file);
            if dep_path.exists() {
                match dep_file {
                    "Cargo.toml" => {
                        if let Ok(analysis) = self.analyze_cargo_dependencies(&dep_path).await {
                            total_dependencies += analysis.0;
                            // In a real implementation, you'd check crates.io API
                        }
                    }
                    "package.json" => {
                        if let Ok(analysis) = self.analyze_npm_dependencies(&dep_path).await {
                            total_dependencies += analysis.0;
                            // In a real implementation, you'd check npm API
                        }
                    }
                    _ => {
                        // Handle other dependency types
                        debug!("Found dependency file: {}", dep_file);
                    }
                }
            }
        }

        Ok(DependencyAnalysis {
            total_dependencies,
            outdated_dependencies,
            vulnerable_dependencies,
            license_issues,
        })
    }

    async fn analyze_cargo_dependencies(&self, cargo_toml: &Path) -> Result<(usize, Vec<String>)> {
        let content = tokio::fs::read_to_string(cargo_toml).await?;

        // Simple parsing - in practice, you'd use proper TOML parsing
        let dependency_count = content
            .lines()
            .filter(|line| line.contains("=") && !line.starts_with('#'))
            .count();

        Ok((dependency_count, Vec::new()))
    }

    async fn analyze_npm_dependencies(&self, package_json: &Path) -> Result<(usize, Vec<String>)> {
        let content = tokio::fs::read_to_string(package_json).await?;

        // In practice, you'd use proper JSON parsing
        let dependency_count = content.matches("\":").count() / 2; // Rough approximation

        Ok((dependency_count, Vec::new()))
    }

    async fn calculate_risk_factors(
        &self,
        _repo_path: &Path,
        file_complexity: &HashMap<String, ComplexityMetrics>,
        _stale_days: u64,
    ) -> Result<Vec<RiskFactor>> {
        let mut risk_factors = Vec::new();

        // High complexity files
        for (file, metrics) in file_complexity {
            if metrics.cyclomatic_complexity > 15.0 {
                risk_factors.push(RiskFactor {
                    factor_type: RiskType::HighComplexity,
                    severity: if metrics.cyclomatic_complexity > 25.0 {
                        RiskSeverity::High
                    } else {
                        RiskSeverity::Medium
                    },
                    description: format!(
                        "File {} has high cyclomatic complexity ({})",
                        file, metrics.cyclomatic_complexity
                    ),
                    affected_files: vec![file.clone()],
                    recommendation: "Consider refactoring to reduce complexity".to_string(),
                });
            }

            if metrics.nesting_depth > 5 {
                risk_factors.push(RiskFactor {
                    factor_type: RiskType::DeepNesting,
                    severity: RiskSeverity::Medium,
                    description: format!(
                        "File {} has deep nesting (depth: {})",
                        file, metrics.nesting_depth
                    ),
                    affected_files: vec![file.clone()],
                    recommendation: "Consider extracting nested logic into separate functions"
                        .to_string(),
                });
            }
        }

        Ok(risk_factors)
    }
}