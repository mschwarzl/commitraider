use anyhow::Result;
use clap::Parser;
use colored::*;
use std::path::PathBuf;
use tracing::{info, Level};

mod analysis;
mod config;
mod git;
mod output;
mod patterns;

use analysis::CodeAnalyzer;
use config::Config;
use git::GitAnalyzer;
use output::agent::AgentReport;
use output::Reporter;
use patterns::PatternEngine;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Repository path to analyze
    #[arg(short, long, required_unless_present("output_schema"))]
    repo: Option<PathBuf>,

    /// Pattern set to use (vuln, autovuln, memorysafety, crypto, web/php, workerd/cpp, all)
    #[arg(short, long, default_value = "vuln")]
    patterns: String,

    /// Output format (html, json, agent-json)
    #[arg(short, long, default_value = "html")]
    output: String,

    /// Output file (report.html|json). If not specified, agent-json outputs to stdout
    #[arg(long)]
    output_file: Option<String>,

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

    /// Maximum commits to analyze on large repos, most recent first (0 = no limit, analyze full history)
    #[arg(long, default_value = "20000")]
    max_commits: usize,

    /// Maximum number of findings and risk files to include in agent-json output
    #[arg(long, default_value = "50")]
    top_n: usize,

    /// Output the JSON schema for agent-json format and exit
    #[arg(long)]
    output_schema: bool,

    /// Use ultra-compact agent-json output. Only applies to --output agent-json
    #[arg(long)]
    compact: bool,
}

fn main() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();

    // Handle schema output - this conflicts with repo-based operations
    if cli.output_schema {
        AgentReport::print_schema();
        return Ok(());
    }

    // Extract repo path early - clap ensures it's Some via required_unless_present
    let repo = cli
        .repo
        .expect("--repo is required when not using --output-schema");

    // Initialize logging to stderr so stdout stays clean for data output
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    if cli.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global()?;
    }

    // Skip banner for agent-json when outputting to stdout (for clean piping)
    let skip_banner =
        matches!(cli.output.as_str(), "agent-json" | "agent") && cli.output_file.is_none();

    if !skip_banner {
        println!(
            "{}",
            "CommitRaider - Git History Security Scanner"
                .bright_cyan()
                .bold()
        );
        println!("Repository: {}", repo.display().to_string().bright_white());
    }

    let config = Config::load()?;
    let pattern_engine = PatternEngine::new(&cli.patterns)?;

    let git_analyzer = GitAnalyzer::new(&repo)?.with_max_commits(cli.max_commits);
    let code_analyzer = CodeAnalyzer::new();
    let mut reporter = Reporter::new(&cli.output, cli.output_file.as_deref())?;

    info!("Starting repository analysis...");

    let git_stats = git_analyzer.analyze().await?;
    info!("Git analysis completed, preparing code analysis...");

    let code_stats = if cli.stats {
        info!("Stats requested, starting code analysis...");
        code_analyzer.analyze(&repo, cli.stale_days).await?
    } else {
        info!("Stats not requested, using default code stats");
        // Create minimal code stats when not requested
        analysis::CodeStats::default()
    };
    info!("Code analysis completed, preparing vulnerability scan...");

    info!("Starting vulnerability pattern scanning...");
    let vulnerabilities = pattern_engine.scan_repository(&repo, &git_stats).await?;
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
        .generate_report(&findings, cli.cve_only, cli.stats, cli.top_n, cli.compact)
        .await?;

    // Skip completion message for agent-json when outputting to stdout
    if !skip_banner {
        println!("\n{}", "Analysis complete!".bright_green().bold());
    }

    Ok(())
}
