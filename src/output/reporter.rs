use super::*;
use crate::analysis::CombinedFindings;
use anyhow::Result;
use std::fs;
use tracing::info;

use super::agent::{AgentReport, CompactAgentReport};
use super::html::HtmlGenerator;

pub struct Reporter {
    format: OutputFormat,
    output_path: Option<String>,
}

impl Reporter {
    pub fn new(format: &str, output_path: Option<&str>) -> Result<Self> {
        let format = OutputFormat::from(format);
        
        // For agent-json, None means stdout
        // For html/json, use default if not provided
        let output_path = match output_path {
            Some(path) => Some(super::add_file_extension(path, &format)),
            None => {
                match format {
                    OutputFormat::AgentJson => None, // stdout
                    _ => Some(super::add_file_extension("report_commit_raider", &format)),
                }
            }
        };

        Ok(Self {
            format,
            output_path,
        })
    }

    pub async fn generate_report(
        &mut self,
        findings: &CombinedFindings,
        cve_only: bool,
        include_stats: bool,
        top_n: usize,
        compact: bool,
    ) -> Result<()> {
        // Warn if --compact is used with non-agent-json formats
        if compact && !matches!(self.format, OutputFormat::AgentJson) {
            tracing::warn!("--compact flag only applies to --output agent-json, ignoring for {:?}", self.format);
        }

        match self.format {
            OutputFormat::Html => {
                let mut generator = HtmlGenerator::new()?;
                let content = generator
                    .generate(findings, cve_only, include_stats)
                    .await?;
                let path = self.output_path.as_ref().expect("HTML output path required");
                fs::write(path, content)?;
                info!("Report saved to {}", path);
            }
            OutputFormat::Json => {
                let content = serde_json::to_string_pretty(findings)?;
                let path = self.output_path.as_ref().expect("JSON output path required");
                fs::write(path, content)?;
                info!("Report saved to {}", path);
            }
            OutputFormat::AgentJson => {
                let content = if compact {
                    // Use ultra-compact format 
                    let compact_report = CompactAgentReport::from_combined_findings(findings);
                    compact_report.generate_json()?
                } else {
                    let agent_report = AgentReport::from_combined_findings(findings, top_n);
                    agent_report.generate_json()?
                };
                
                match &self.output_path {
                    Some(path) => {
                        // Write to file if path specified
                        fs::write(path, content)?;
                        info!("Agent-json report saved to {}", path);
                    }
                    None => {
                        // Output to stdout for easy piping
                        println!("{}", content);
                        info!("Agent-json report output to stdout");
                    }
                }
            }
        };

        Ok(())
    }
}
