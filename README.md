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

# Compact JSON for AI agent consumption
commitraider --repo /path/to/repository --output agent-json --top-n 50

# Analyze with code complexity metrics
commitraider --repo /path/to/repository --output json --stats

# Show only security fixes with CVE references
commitraider --repo /path/to/repository --output json --cve-only

# Export JSON Schema for validation
commitraider --output-schema > agent-report-schema.json

# Ultra-compact mode for tools with character limits (<30k chars)
commitraider --repo /path/to/repository --output agent-json --compact
```

### AI/Agent Integration

For AI assistants that need to analyze repository security:

```bash
# Recommended: use agent-json with bounded output
commitraider --repo /path/to/repo --output agent-json --top-n 20 --stats

# Compact mode
commitraider --repo /path/to/repo --output agent-json --compact

# The agent-json output includes:
# - Overall risk score (0-10)
# - Critical/high finding counts
# - CVE references
# - Risky files (single author, stale, complex)
# - Vulnerable dependencies
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
  -o, --output <OUTPUT>          Output format (html, json, agent-json) [default: html]
  -p, --patterns <PATTERNS>      Pattern set to use (vuln, memory, crypto, all) [default: vuln]
      --output-file <OUTPUT_FILE> Output file name. If not specified, agent-json outputs to stdout
  -c, --cve-only                 Show only CVE references
  -s, --stats                    Include detailed statistics and code complexity analysis
      --stale-days <STALE_DAYS>  Minimum days since last commit to flag as stale [default: 365]
      --top-n <TOP_N>            Maximum findings/risk files in agent-json output [default: 50]
      --output-schema            Output the JSON schema for agent-json format and exit
      --compact                  Use ultra-compact agent-json output (<30k chars). Only applies to --output agent-json
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

#### JSON (`--output json`)
Machine-readable output for CI/CD pipeline integration. Note: this format can be very large for big repositories as it includes the complete commit history and file metadata.

#### Agent-JSON (`--output agent-json`) *[Recommended for AI/Agent consumption]*
A compact, bounded JSON format optimized for AI agents and automated tools:

- **10x smaller** than regular JSON on large repositories
- **Bounded output**: `--top-n` limits findings and risk files (default 50)
- **Pre-calculated summaries**: Risk scores, severity levels, and CVE counts
- **Schema validation**: Use `--output-schema` to get the JSON Schema

Example:
```bash
# Basic agent-friendly output (50 items max)
commitraider --repo /path/to/repo --output agent-json

# Limited output for very large repos
commitraider --repo /path/to/repo --output agent-json --top-n 20

# With code complexity metrics
commitraider --repo /path/to/repo --output agent-json --stats

# Get the JSON Schema
commitraider --output-schema > schema.json
```

**Ultra-Compact Mode (`--compact`):**
For tools with strict character limits (e.g., 30,000 char tool output limits):

```bash
# Ultra-compact output (~5-20k chars, <30k guaranteed)
commitraider --repo /path/to/repo --output agent-json --compact
```

The `--compact` flag produces a condensed report with:
- Shortened field names (e.g., `v`, `repo`, `risk`, `vulns`, `files`)
- Top 15 vulnerability findings including:
  - Short commit ID (8 chars)
  - Truncated commit message (120 chars max)
  - Risk score and severity
  - Pattern names, severities, and categories
  - CVE references
  - Changed files (basenames only)
- Top 10 risk files
- Summary counts by severity

**Agent-JSON Structure:**
- `repository`: Repository metadata (path, commits, files, authors)
- `summary`: High-level risk overview (scores, CVE counts, risk file counts)
- `findings`: Top-N vulnerability findings sorted by risk score
- `risk_files`: High-risk files (complexity, ownership, staleness issues)
- `dependencies`: Outdated/vulnerable dependency information

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
