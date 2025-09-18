use anyhow::Result;
use serde::{Deserialize, Serialize};

pub mod html;
pub mod reporter;
pub mod sarif;

pub use reporter::Reporter;

use crate::analysis::CombinedFindings;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Html,
}

impl From<&str> for OutputFormat {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "html" => OutputFormat::Html,
            _ => OutputFormat::Html,
        }
    }
}

pub fn add_file_extension(path: &str, format: &OutputFormat) -> String {
    let extension = match format {
        OutputFormat::Html => ".html",
        OutputFormat::Json => ".json",
    };

    if path.ends_with(extension) {
        path.to_string()
    } else {
        format!("{}{}", path, extension)
    }
}

pub trait OutputGenerator {
    async fn generate(
        &mut self,
        findings: &CombinedFindings,
        cve_only: bool,
        include_stats: bool,
    ) -> Result<String>;
}
