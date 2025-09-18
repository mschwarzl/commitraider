use super::*;
use crate::analysis::CombinedFindings;
use anyhow::Result;
use std::fs;
use tracing::info;

use super::html::HtmlGenerator;

pub struct Reporter {
    format: OutputFormat,
    output_path: String,
}

impl Reporter {
    pub fn new(format: &str, output_path: &str) -> Result<Self> {
        let format = OutputFormat::from(format);
        let output_path = super::add_file_extension(output_path, &format);

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
    ) -> Result<()> {
        let content = match self.format {
            OutputFormat::Html => {
                let mut generator = HtmlGenerator::new()?;
                generator
                    .generate(findings, cve_only, include_stats)
                    .await?
            }
            OutputFormat::Json => serde_json::to_string_pretty(findings)?,
        };

        fs::write(&self.output_path, content)?;
        info!("Report saved to {}", self.output_path);
        Ok(())
    }
}
