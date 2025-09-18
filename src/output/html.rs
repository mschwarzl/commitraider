use super::*;
use crate::analysis::CombinedFindings;
use crate::git::RepositoryLinker;
use crate::patterns::VulnerabilityFinding;
use anyhow::Result;
use chrono::Utc;
use rust_embed::RustEmbed;
use serde_json::{json, Value};
use std::collections::HashMap;
use tera::{Context, Tera};

#[derive(RustEmbed)]
#[folder = "src/output/templates/"]
#[include = "*.html"]
struct Templates;

#[derive(RustEmbed)]
#[folder = "src/output/assets/"]
#[include = "*.css"]
#[include = "*.js"]
struct Assets;

pub struct HtmlGenerator {
    tera: Tera,
}

struct HeatmapData {
    files: Vec<Value>,
    stats: Value,
}

impl HtmlGenerator {
    pub fn new() -> Result<Self> {
        let mut tera = Tera::default();

        // Load templates from embedded resources
        for file in Templates::iter() {
            let template_name = file.as_ref();
            let template_content = Templates::get(template_name)
                .ok_or_else(|| anyhow::anyhow!("Template {} not found", template_name))?;
            let template_str = std::str::from_utf8(&template_content.data)
                .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in template {}: {}", template_name, e))?;

            tera.add_raw_template(template_name, template_str)
                .map_err(|e| anyhow::anyhow!("Failed to add template {}: {}", template_name, e))?;
        }

        // Add custom filters if needed
        tera.register_filter("severity_class", Self::severity_class_filter);
        tera.register_filter("risk_class", Self::risk_class_filter);
        tera.register_filter("severity_text", Self::severity_text_filter);

        Ok(Self { tera })
    }

    fn load_asset(&self, filename: &str) -> Result<String> {
        let asset = Assets::get(filename)
            .ok_or_else(|| anyhow::anyhow!("Asset {} not found", filename))?;
        let content = std::str::from_utf8(&asset.data)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in asset {}: {}", filename, e))?;
        Ok(content.to_string())
    }

    fn severity_class_filter(value: &Value, _: &HashMap<String, Value>) -> tera::Result<Value> {
        let risk_score = value.as_f64().unwrap_or(0.0);
        let class = if risk_score >= 8.0 {
            "severity-critical"
        } else if risk_score >= 6.0 {
            "severity-high"
        } else if risk_score >= 4.0 {
            "severity-medium"
        } else if risk_score >= 2.0 {
            "severity-low"
        } else {
            "severity-info"
        };
        Ok(Value::String(class.to_string()))
    }

    fn risk_class_filter(value: &Value, _: &HashMap<String, Value>) -> tera::Result<Value> {
        let risk_score = value.as_f64().unwrap_or(0.0);
        let class = if risk_score >= 8.0 {
            "risk-critical"
        } else if risk_score >= 6.0 {
            "risk-high"
        } else if risk_score >= 4.0 {
            "risk-medium"
        } else {
            "risk-low"
        };
        Ok(Value::String(class.to_string()))
    }

    fn severity_text_filter(value: &Value, _: &HashMap<String, Value>) -> tera::Result<Value> {
        let risk_score = value.as_f64().unwrap_or(0.0);
        let text = if risk_score >= 8.0 {
            "critical"
        } else if risk_score >= 6.0 {
            "high"
        } else if risk_score >= 4.0 {
            "medium"
        } else if risk_score >= 2.0 {
            "low"
        } else {
            "info"
        };
        Ok(Value::String(text.to_string()))
    }

    fn prepare_template_context(
        &self,
        findings: &CombinedFindings,
        cve_only: bool,
        include_stats: bool,
    ) -> Result<Context> {
        let mut context = Context::new();

        // Load CSS and JavaScript content
        let css_content = self.load_asset("styles.css")?;
        let js_content = self.load_asset("script.js")?;

        context.insert("css_content", &css_content);
        context.insert("js_content", &js_content);
        context.insert("repo_path", &findings.git_stats.path);
        context.insert(
            "generated_date",
            &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );
        context.insert("findings", findings);
        context.insert("include_stats", &include_stats);
        context.insert("cve_only", &cve_only);

        // Risk overview calculations
        let overall_risk = findings.calculate_overall_risk();
        let risk_percentage = (overall_risk / 10.0 * 100.0) as u32;

        context.insert("overall_risk", &overall_risk);
        context.insert("risk_percentage", &risk_percentage);

        let single_author_percentage = findings.git_stats.single_author_files.len() as f64
            / findings.git_stats.total_files as f64
            * 100.0;
        let stale_files_percentage = findings.git_stats.stale_files.len() as f64
            / findings.git_stats.total_files as f64
            * 100.0;
        let high_complexity_count = findings
            .code_stats
            .file_complexity
            .values()
            .filter(|c| c.cyclomatic_complexity > 10.0)
            .count();

        context.insert("single_author_percentage", &single_author_percentage);
        context.insert("stale_files_percentage", &stale_files_percentage);
        context.insert("high_complexity_count", &high_complexity_count);

        // Vulnerability data
        let filtered_vulnerabilities: Vec<_> = if cve_only {
            findings
                .vulnerabilities
                .iter()
                .filter(|v| !v.cve_references.is_empty())
                .collect()
        } else {
            findings.vulnerabilities.iter().collect()
        };

        let show_vulnerabilities = !filtered_vulnerabilities.is_empty();
        context.insert("show_vulnerabilities", &show_vulnerabilities);
        context.insert(
            "filtered_vulnerabilities",
            &self.prepare_vulnerability_data_with_links(&filtered_vulnerabilities, findings),
        );

        // Code quality data
        let high_complexity_files: Vec<_> = findings
            .code_stats
            .file_complexity
            .iter()
            .filter(|(_, metrics)| metrics.cyclomatic_complexity > 10.0)
            .take(10)
            .collect();
        context.insert("high_complexity_files", &high_complexity_files);

        // All complexity files (sorted by complexity for full analysis)
        let mut all_complexity_files: Vec<_> = findings
            .code_stats
            .file_complexity
            .iter()
            .collect();
        all_complexity_files.sort_by(|a, b| {
            b.1.cyclomatic_complexity
                .partial_cmp(&a.1.cyclomatic_complexity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        context.insert("all_complexity_files", &all_complexity_files);

        // Git analysis data
        let top_contributors = findings.git_stats.get_top_contributors(5);
        context.insert("top_contributors", &top_contributors);

        // Heatmap data with repository links
        let linker = RepositoryLinker::new(&findings.git_stats);
        let heatmap_data = self.prepare_heatmap_data(&findings, &linker);
        context.insert("heatmap_files", &heatmap_data.files);
        context.insert("heatmap_stats", &heatmap_data.stats);

        // Priority areas: group findings by file
        let linker = RepositoryLinker::new(&findings.git_stats);
        let mut file_findings: std::collections::HashMap<String, Vec<&VulnerabilityFinding>> =
            std::collections::HashMap::new();

        // Group vulnerabilities by file
        for finding in &findings.vulnerabilities {
            for file in &finding.files_changed {
                file_findings.entry(file.clone()).or_default().push(finding);
            }
        }

        // Sort files by number of findings (descending) and convert to JSON
        let mut priority_files: Vec<_> = file_findings
            .iter()
            .map(|(file, findings_vec)| {
                let high_risk_count = findings_vec.iter().filter(|f| f.risk_score >= 7.0).count();
                let medium_risk_count = findings_vec
                    .iter()
                    .filter(|f| f.risk_score >= 4.0 && f.risk_score < 7.0)
                    .count();
                let low_risk_count = findings_vec.iter().filter(|f| f.risk_score < 4.0).count();

                let file_url = linker.get_file_url(file, None);

                (
                    file,
                    findings_vec.len(),
                    high_risk_count,
                    medium_risk_count,
                    low_risk_count,
                    file_url,
                )
            })
            .collect();

        priority_files.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by total findings count descending

        let priority_areas_by_file: Vec<_> = priority_files
            .into_iter()
            .take(15) // Show top 15 files with most findings
            .map(
                |(file, total_count, high_count, medium_count, low_count, file_url)| {
                    // Find the most recent commit that modified this file
                    let recent_commit = findings.git_stats.file_history.get(file)
                        .and_then(|history| {
                            // Get the most recent commit from the history
                            history.commits.last().cloned()
                        });

                    let (commit_url, commit_id_short) = if let Some(commit_id) = &recent_commit {
                        let commit_url = linker.get_commit_url(commit_id);
                        let commit_id_short = if commit_id.len() >= 8 {
                            &commit_id[..8]
                        } else {
                            commit_id
                        };
                        (commit_url, commit_id_short.to_string())
                    } else {
                        (None, "".to_string())
                    };

                    // Get the actual findings for this file
                    let findings_for_file: Vec<_> = file_findings.get(file).unwrap_or(&Vec::new())
                        .iter()
                        .map(|finding| {
                            let commit_url = linker.get_commit_url(&finding.commit_id);
                            let diff_url = linker.get_diff_url(&finding.commit_id);
                            let commit_id_short = if finding.commit_id.len() >= 8 {
                                &finding.commit_id[..8]
                            } else {
                                &finding.commit_id
                            };

                            json!({
                                "commit_message": finding.commit_message.lines().next().unwrap_or("").to_string(),
                                "commit_id": finding.commit_id,
                                "commit_id_short": commit_id_short,
                                "commit_url": commit_url,
                                "diff_url": diff_url,
                                "risk_score": finding.risk_score,
                                "severity_class": self.get_severity_class(finding.risk_score),
                                "patterns_matched": finding.patterns_matched,
                                "date": finding.date,
                                "author": finding.author
                            })
                        })
                        .collect();

                    json!({
                        "file": file,
                        "total_findings": total_count,
                        "high_risk_findings": high_count,
                        "medium_risk_findings": medium_count,
                        "low_risk_findings": low_count,
                        "file_url": file_url,
                        "recent_commit_id": recent_commit,
                        "commit_id_short": commit_id_short,
                        "commit_url": commit_url,
                        "findings": findings_for_file
                    })
                },
            )
            .collect();
        context.insert("priority_areas", &priority_areas_by_file);

        // Single author files with extension analysis
        let single_author_files: Vec<_> = findings
            .git_stats
            .single_author_files
            .iter()
            .take(20)
            .collect();
        context.insert("single_author_files", &single_author_files);

        // File extension distributions
        let single_author_extensions =
            self.calculate_extension_distribution(&findings.git_stats.single_author_files);
        let stale_files_extensions =
            self.calculate_extension_distribution(&findings.git_stats.stale_files);
        context.insert("single_author_extensions", &single_author_extensions);
        context.insert("stale_files_extensions", &stale_files_extensions);

        // Repository links and metadata
        let linker = RepositoryLinker::new(&findings.git_stats);
        context.insert("repository_type", &findings.git_stats.repository_type);
        context.insert("repository_name", &linker.get_repository_name());

        // Use the cleaned-up base URL instead of raw remote_url
        let base_url = linker.get_base_url();
        context.insert("remote_url", &base_url);

        // Test analysis (limit patterns found to 10 for display)
        let mut test_analysis = findings.git_stats.test_analysis.clone();
        test_analysis.test_patterns_found = test_analysis
            .test_patterns_found
            .into_iter()
            .take(10)
            .collect();
        context.insert("test_analysis", &test_analysis);

        Ok(context)
    }

    fn prepare_vulnerability_data_with_links(
        &self,
        vulnerabilities: &[&crate::patterns::VulnerabilityFinding],
        findings: &CombinedFindings,
    ) -> Vec<serde_json::Value> {
        let linker = RepositoryLinker::new(&findings.git_stats);

        vulnerabilities.iter().map(|vuln| {
            let commit_url = linker.get_commit_url(&vuln.commit_id);
            let diff_url = linker.get_diff_url(&vuln.commit_id);
            let issue_refs = linker.extract_issue_references(&vuln.commit_message);

            let issue_links: Vec<_> = issue_refs.iter()
                .filter_map(|issue_num| {
                    linker.get_issue_url(issue_num).map(|url| {
                        json!({
                            "number": issue_num,
                            "url": url
                        })
                    })
                })
                .collect();

            let file_links: Vec<_> = vuln.files_changed.iter()
                .filter_map(|file| {
                    linker.get_file_url(file, Some(&vuln.commit_id)).map(|url| {
                        json!({
                            "path": file,
                            "url": url
                        })
                    })
                })
                .collect();

            json!({
                "commit_id": vuln.commit_id,
                "commit_id_short": if vuln.commit_id.len() >= 8 { &vuln.commit_id[..8] } else { &vuln.commit_id },
                "commit_message": vuln.commit_message,
                "author": vuln.author,
                "date": vuln.date,
                "files_changed": vuln.files_changed,
                "patterns_matched": vuln.patterns_matched,
                "risk_score": vuln.risk_score,
                "cve_references": vuln.cve_references,
                "severity_class": self.get_severity_class(vuln.risk_score),
                "risk_class": self.get_risk_class(vuln.risk_score),
                "severity_text": self.get_severity_text(vuln.risk_score),
                "commit_url": commit_url,
                "diff_url": diff_url,
                "issue_links": issue_links,
                "file_links": file_links
            })
        }).collect()
    }

    fn prepare_heatmap_data(
        &self,
        findings: &CombinedFindings,
        linker: &RepositoryLinker,
    ) -> HeatmapData {
        // Calculate commit frequencies for all files
        let mut file_commit_counts = std::collections::HashMap::new();

        for commit in &findings.git_stats.commit_history {
            for file in &commit.files_changed {
                *file_commit_counts.entry(file.clone()).or_insert(0) += 1;
            }
        }

        // Determine thresholds for color coding
        let max_commits = file_commit_counts.values().max().unwrap_or(&0);
        let threshold_1 = max_commits / 5;
        let threshold_2 = max_commits * 2 / 5;
        let threshold_3 = max_commits * 3 / 5;
        let threshold_4 = max_commits * 4 / 5;

        // Create sorted list of files by commit count (descending) - limit to top 100
        let mut sorted_files: Vec<_> = file_commit_counts.iter().collect();
        sorted_files.sort_by(|a, b| b.1.cmp(a.1));

        let files: Vec<_> = sorted_files
            .iter()
            //.take(100)
            .map(|(file, &count)| {
                let css_class = if count == 0 {
                    "commits-0"
                } else if count <= threshold_1 {
                    "commits-1"
                } else if count <= threshold_2 {
                    "commits-2"
                } else if count <= threshold_3 {
                    "commits-3"
                } else if count <= threshold_4 {
                    "commits-4"
                } else {
                    "commits-high"
                };

                // Get file extension for icon
                let extension = std::path::Path::new(file)
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("file");

                // Extract just the filename for better readability
                let display_name = std::path::Path::new(file)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(file)
                    .to_string();

                let display_name = if display_name.len() > 15 {
                    format!("{}...", &display_name[..12])
                } else {
                    display_name
                };

                // Get authors and last modified info from git stats
                let authors: Vec<String> = findings
                    .git_stats
                    .file_history
                    .get(*file)
                    .map(|history| history.authors.iter().cloned().collect())
                    .unwrap_or_default();

                let authors_str = if authors.is_empty() {
                    "Unknown".to_string()
                } else if authors.len() <= 3 {
                    authors.join(", ")
                } else {
                    format!(
                        "{}, {} and {} more",
                        authors[0],
                        authors[1],
                        authors.len() - 2
                    )
                };

                let last_modified = findings
                    .git_stats
                    .file_history
                    .get(*file)
                    .map(|history| history.last_commit.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                // Get file URL using the repository linker
                let file_url = linker.get_file_url(file, None);

                json!({
                    "path": file,
                    "commit_count": count,
                    "css_class": css_class,
                    "extension": extension,
                    "display_name": display_name,
                    "authors": authors_str,
                    "last_modified": last_modified,
                    "file_url": file_url
                })
            })
            .collect();

        let high_churn_files = file_commit_counts
            .values()
            .filter(|&&c| c > threshold_4)
            .count();
        let medium_churn_files = file_commit_counts
            .values()
            .filter(|&&c| c > threshold_2 && c <= threshold_4)
            .count();
        let low_churn_files = file_commit_counts
            .values()
            .filter(|&&c| c <= threshold_2)
            .count();

        let stats = json!({
            "high_churn_files": high_churn_files,
            "medium_churn_files": medium_churn_files,
            "low_churn_files": low_churn_files,
            "threshold_2": threshold_2,
            "threshold_4": threshold_4
        });

        HeatmapData { files, stats }
    }

    fn get_severity_class(&self, risk_score: f64) -> &'static str {
        if risk_score >= 8.0 {
            "severity-critical"
        } else if risk_score >= 6.0 {
            "severity-high"
        } else if risk_score >= 4.0 {
            "severity-medium"
        } else if risk_score >= 2.0 {
            "severity-low"
        } else {
            "severity-info"
        }
    }

    fn get_risk_class(&self, risk_score: f64) -> &'static str {
        if risk_score >= 8.0 {
            "risk-critical"
        } else if risk_score >= 6.0 {
            "risk-high"
        } else if risk_score >= 4.0 {
            "risk-medium"
        } else {
            "risk-low"
        }
    }

    fn get_severity_text(&self, risk_score: f64) -> &'static str {
        if risk_score >= 8.0 {
            "critical"
        } else if risk_score >= 6.0 {
            "high"
        } else if risk_score >= 4.0 {
            "medium"
        } else if risk_score >= 2.0 {
            "low"
        } else {
            "info"
        }
    }

    fn calculate_extension_distribution(&self, files: &[String]) -> Vec<serde_json::Value> {
        let mut extension_counts = HashMap::new();
        let mut no_extension_count = 0;

        for file in files {
            if let Some(extension) = std::path::Path::new(file)
                .extension()
                .and_then(|s| s.to_str())
            {
                *extension_counts
                    .entry(extension.to_lowercase())
                    .or_insert(0) += 1;
            } else {
                no_extension_count += 1;
            }
        }

        let mut distribution: Vec<_> = extension_counts
            .into_iter()
            .map(|(ext, count)| {
                let percentage = (count as f64 / files.len() as f64) * 100.0;
                json!({
                    "extension": ext,
                    "count": count,
                    "percentage": percentage
                })
            })
            .collect();

        // Sort by count descending
        distribution.sort_by(|a, b| {
            b["count"]
                .as_u64()
                .unwrap_or(0)
                .cmp(&a["count"].as_u64().unwrap_or(0))
        });

        // Add "no extension" category if there are files without extensions
        if no_extension_count > 0 {
            let percentage = (no_extension_count as f64 / files.len() as f64) * 100.0;
            distribution.push(json!({
                "extension": "no extension",
                "count": no_extension_count,
                "percentage": percentage
            }));
        }

        distribution
    }
}

impl OutputGenerator for HtmlGenerator {
    async fn generate(
        &mut self,
        findings: &CombinedFindings,
        cve_only: bool,
        include_stats: bool,
    ) -> Result<String> {
        let context = self.prepare_template_context(findings, cve_only, include_stats)?;
        let html = self.tera.render("report.html", &context)?;
        Ok(html)
    }
}
