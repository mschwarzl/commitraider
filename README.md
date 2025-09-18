# CommitRaider

**Git History Security Scanner**

Often in code reviews or security research, the entrypoint, i.e. which files to look at, is hard to find. CommitRaider is a tool that examines Git commit history to historical security fixes within codebases.
The tool analyzes commit messages, file modifications, and code patterns to provide security insights into Git repositories. Additionally, the tool tries to measure code complexity. You can find an example report in `example_reports`. Note, CommitRaider meant as helper to quickly familiarize yourself with the code and not as **replacement** to SAST/DAST tools.

## Core Functionality

- **Vulnerability Pattern Detection**: Identifies commits containing security-related keywords, patterns, and fixes
- **Risk Scoring**: Assigns numerical risk scores to identified issues based on configurable criteria
- **Historical Analysis**: Provides chronological mapping of security-related commits
- **Pattern Matching**: Uses configurable regex patterns to detect common vulnerability indicators
- **Code Metrics**: Analyzes code complexity, file ownership patterns, and maintenance status
- **One-site report**: Generates a static page including all necessary information

## Usage Examples

```bash
# Basic repository scan with HTML output
commitraider --repo /path/to/repository --output html
```

## Installation

### Building from Source
```bash
git clone <repository-url>
cd commitraider
cargo build --release
```

### Installing the package
```bash
cd commitraider
cargo install --path .
```

## Command Line Interface

```
CommitRaider - Git Scanner that raids commit history for vulnerabilities

Usage: commitraider [OPTIONS] --repo <REPO>

Options:
  -r, --repo <REPO>              Path to Git repository to analyze
  -o, --output <OUTPUT>          Output format (html, json) [default: html]
  -c, --cve-only                Show only CVE references
  -s, --stats                    Include detailed statistics and code complexity analysis
      --stale-days <STALE_DAYS>  Minimum days since last commit to flag as stale [default: 365]
  -v, --verbose                  Enable verbose logging
  -t, --threads <THREADS>        Number of threads for Rayon parallel vulnerability scanning (0 = auto-detect CPU cores) [default: 0]
  -h, --help                     Print help
```

## Output Formats

### HTML Reports
Interactive web-based reports featuring:
- Visual dashboards and statistical summaries
- Search and filtering capabilities for large datasets
- Direct links to commits, files, and repository issues
- Temporal analysis with commit activity heatmaps
- File type distribution and risk categorization

### Structured Data Formats
- **JSON**: Machine-readable output for CI/CD pipeline integration

## Detection Capabilities

### Security Patterns
CommitRaider scans for typical messages used to fix/patch a potential vulnerability:

- **Fix commits** with security-related messages
- **CVE references** and security advisories
- **Emergency patches** and hotfixes
- **Security hardening** improvements
- **Dependency updates** for known vulnerabilities

### Code Quality Issues
CommitRaider also highlights the following issues:

- **High complexity files** that may hide vulnerabilities using simplistic halstead volume
- **Single author files** lacking code review
- **Stale files** not updated recently
- **High churn files** with frequent changes
- **Large commits** that may introduce issues
