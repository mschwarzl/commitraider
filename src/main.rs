use anyhow::Result;
use clap::Parser;
use colored::*;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber;

mod analysis;
mod config;
mod git;
mod output;
mod patterns;

use analysis::CodeAnalyzer;
use config::Config;
use git::GitAnalyzer;
use output::Reporter;
use patterns::PatternEngine;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Repository path to analyze
    #[arg(short, long)]
    repo: PathBuf,

    /// Pattern set to use (vuln, memory, crypto, all)
    #[arg(short, long, default_value = "vuln")]
    patterns: String,

    /// Output format (html, json)
    #[arg(short, long, default_value = "html")]
    output: String,

    /// Output file (report.html|json)
    #[arg(long, default_value = "report_commit_raider")]
    output_file: String,

    /// Show only CVE references
    #[arg(short, long)]
    cve_only: bool,

    /// Include detailed statistics
    #[arg(short, long)]
    stats: bool,

    /// Minimum days since last commit to flag as stale
    #[arg(long, default_value = "365")]
    stale_days: u64,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Number of threads for Rayon parallel vulnerability scanning (0 = auto-detect CPU cores)
    #[arg(short, long, default_value = "0")]
    threads: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    if cli.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global()?;
    }

    println!(
        "{}",
        "CommitRaider - Git History Security Scanner"
            .bright_cyan()
            .bold()
    );
    println!(
        "Repository: {}",
        cli.repo.display().to_string().bright_white()
    );

    let config = Config::load()?;
    let pattern_engine = PatternEngine::new(&cli.patterns)?;

    let git_analyzer = GitAnalyzer::new(&cli.repo)?;
    let code_analyzer = CodeAnalyzer::new();
    let mut reporter = Reporter::new(&cli.output, &cli.output_file)?;

    info!("Starting repository analysis...");

    let git_stats = git_analyzer.analyze().await?;
    info!("Git analysis completed, preparing code analysis...");

    let code_stats = if cli.stats {
        info!("Stats requested, starting code analysis...");
        code_analyzer.analyze(&cli.repo, cli.stale_days).await?
    } else {
        info!("Stats not requested, using default code stats");
        // Create minimal code stats when not requested
        analysis::CodeStats::default()
    };
    info!("Code analysis completed, preparing vulnerability scan...");

    info!("Starting vulnerability pattern scanning...");
    let vulnerabilities = pattern_engine
        .scan_repository(&cli.repo, &git_stats)
        .await?;
    info!(
        "Pattern scanning complete, found {} vulnerabilities",
        vulnerabilities.len()
    );

    let findings = analysis::CombinedFindings {
        git_stats,
        code_stats,
        vulnerabilities,
        config: config.clone(),
    };

    reporter
        .generate_report(&findings, cli.cve_only, cli.stats)
        .await?;

    println!("\n{}", "Analysis complete!".bright_green().bold());

    Ok(())
}
