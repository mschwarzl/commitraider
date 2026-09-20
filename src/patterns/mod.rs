use serde::{Deserialize, Serialize};

pub mod engine;

pub use engine::PatternEngine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPattern {
    pub name: String,
    pub pattern: String,
    pub severity: Severity,
    pub category: Category,
    pub description: String,
    pub cwe: Option<String>,
    pub examples: Vec<String>,
    /// Which text the pattern is matched against.
    #[serde(default)]
    pub target: MatchTarget,
    /// If non-empty, the pattern only fires when at least one of these
    /// (case-insensitive) substrings is also present in the scanned text.
    /// Used to require a *security* context (e.g. only flag MD5 near
    /// `password`/`token`/`hmac`).
    #[serde(default)]
    pub require_near: Vec<String>,
    /// If any of these (case-insensitive) substrings is present in the scanned
    /// text, the match is suppressed. Used to drop benign contexts (e.g. MD5 as
    /// an S3 `Content-MD5` integrity header or a filecache key).
    #[serde(default)]
    pub suppress_near: Vec<String>,
    /// If non-empty, the pattern only fires when the commit touches a file whose
    /// path ends with one of these (e.g. `.c++`, `.cpp`, `.h` for workerd/KJ
    /// C++ rules). Keeps language-specific rules from polluting other targets.
    #[serde(default)]
    pub lang_ext: Vec<String>,
    /// Named ruleset this pattern belongs to (e.g. "workerd"). Selected via the
    /// `--patterns <ruleset>` option; empty = part of the general set.
    #[serde(default)]
    pub ruleset: String,
}

/// Where a pattern is evaluated.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum MatchTarget {
    /// Commit subject/body only (weak evidence — terse security fixes miss it).
    #[default]
    Message,
    /// Changed (added/removed) source lines only — high signal in mature repos.
    Diff,
    /// Both message and diff.
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    #[default]
    Info,
}

impl Severity {
    /// Ordering rank, highest first. Used to pick the worst severity of a set.
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }

    /// Step this severity down `n` levels (Critical -> High -> ... -> Info).
    pub fn demote(&self, n: u8) -> Severity {
        let mut rank = self.rank().saturating_sub(n).max(1);
        if rank > 5 {
            rank = 5;
        }
        match rank {
            5 => Severity::Critical,
            4 => Severity::High,
            3 => Severity::Medium,
            2 => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Lowercase label used by every output format.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub enum Category {
    MemorySafety,
    Cryptography,
    WebSecurity,
    InputValidation,
    AuthenticationAuthorization,
    Concurrency,
    DataExposure,
    CodeInjection,
    #[default]
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub matched_text: String,
    pub severity: Severity,
    pub category: Category,
    pub file_path: String,
    pub line_number: Option<usize>,
    pub context: String,
    pub cve_references: Vec<String>,
    /// Chromium/crbug tracker IDs found alongside this match (`Bug:`/`Fixed:`
    /// trailers, `crbug.com/<id>`, `issues.chromium.org/issues/<id>`).
    #[serde(default)]
    pub bug_references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub commit_id: String,
    pub commit_message: String,
    pub author: String,
    pub date: chrono::DateTime<chrono::Utc>,
    pub files_changed: Vec<String>,
    pub patterns_matched: Vec<PatternMatch>,
    pub risk_score: f64,
    pub cve_references: Vec<String>,
    /// Chromium/crbug tracker IDs referenced by this commit, deduplicated
    /// across its matched patterns. Lets a finding be cross-checked against
    /// the actual tracked bug (severity, disclosure status, duplicates)
    /// instead of only the commit message text.
    #[serde(default)]
    pub bug_references: Vec<String>,
    /// Number of commits (across branches) sharing this fix. 1 for a normal
    /// commit; >1 when the same fix was backported — a strong CVE signal.
    #[serde(default = "one")]
    pub backport_count: usize,
    /// Capped changed-lines diff snippet for downstream triage.
    #[serde(default)]
    pub diff_snippet: String,
}

impl VulnerabilityFinding {
    /// Canonical severity of a finding: the highest declared severity among the
    /// patterns it matched, capped by what the evidence score supports.
    ///
    /// This is the single source of truth for severity across every output
    /// format. Do not re-derive severity from `risk_score`: the score is a
    /// heuristic blend of pattern weight, churn and file age, so thresholding it
    /// produces a different answer than the pattern's own classification and the
    /// formats then disagree with each other.
    pub fn severity(&self) -> Severity {
        let class = self
            .patterns_matched
            .iter()
            .map(|p| p.severity.clone())
            .max_by_key(|s| s.rank())
            .unwrap_or(Severity::Info);

        // The pattern class is the answer: a commit whose message says it fixes
        // a use-after-free is a critical-class security fix, and message-only
        // matching is the normal case for commit mining rather than weak
        // evidence. The one case that is genuinely not about this project's
        // code is a commit that touches no source file at all, such as a
        // dependency roll quoting an upstream changelog. Those drop hard.
        let touches_source = self
            .files_changed
            .iter()
            .any(|f| crate::patterns::engine::is_source_file(f));

        if touches_source {
            class
        } else {
            class.demote(3)
        }
    }
}

fn one() -> usize {
    1
}

// --- pattern constructors (keep the pattern table terse) --------------------

fn msg(
    name: &str,
    pattern: &str,
    severity: Severity,
    category: Category,
    cwe: &str,
) -> VulnerabilityPattern {
    VulnerabilityPattern {
        name: name.to_string(),
        pattern: pattern.to_string(),
        severity,
        category,
        description: name.to_string(),
        cwe: if cwe.is_empty() {
            None
        } else {
            Some(cwe.to_string())
        },
        examples: Vec::new(),
        target: MatchTarget::Message,
        require_near: Vec::new(),
        suppress_near: Vec::new(),
        lang_ext: Vec::new(),
        ruleset: String::new(),
    }
}

fn diff(
    name: &str,
    pattern: &str,
    severity: Severity,
    category: Category,
    cwe: &str,
) -> VulnerabilityPattern {
    VulnerabilityPattern {
        target: MatchTarget::Diff,
        ..msg(name, pattern, severity, category, cwe)
    }
}

/// C/C++ file extensions for language-gated rules (workerd/KJ).
fn cpp_exts() -> Vec<String> {
    [
        ".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".h++", ".capnp",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// A workerd/KJ-specific C++ rule: gated to C/C++ files and tagged `workerd`.
fn workerd(
    name: &str,
    pattern: &str,
    severity: Severity,
    category: Category,
    cwe: &str,
) -> VulnerabilityPattern {
    VulnerabilityPattern {
        lang_ext: cpp_exts(),
        ruleset: "workerd".to_string(),
        ..msg(name, pattern, severity, category, cwe)
    }
}

/// Rules for the bug classes the agent campaigns actually produce: broken
/// authorization, injection, signature verification, replay, resource
/// exhaustion and checker-soundness bugs. Matches message and diff.
fn autovuln(
    name: &str,
    pattern: &str,
    severity: Severity,
    category: Category,
    cwe: &str,
) -> VulnerabilityPattern {
    VulnerabilityPattern {
        target: MatchTarget::Both,
        ruleset: "autovuln".to_string(),
        ..msg(name, pattern, severity, category, cwe)
    }
}

pub fn default_patterns() -> Vec<VulnerabilityPattern> {
    let mut v = vec![
        // ---- Message-keyword patterns (weak evidence, high-precision vocab) --
        msg(
            "Authorization Bypass / IDOR",
            r"(?i)\b(auth(?:entication|oriz(?:ation)?)?[-\s]bypass|privilege[-\s]escalation|idor|insecure[-\s]direct[-\s]object|broken[-\s]access[-\s]control|missing[-\s]authoriz|access[-\s]control)\b",
            Severity::Critical,
            Category::AuthenticationAuthorization,
            "CWE-639",
        ),
        msg(
            "Injection / RCE",
            r"(?i)\b(code[-\s]injection|command[-\s]injection|sql[-\s]injection|remote[-\s]code[-\s]execution|\brce\b)\b",
            Severity::Critical,
            Category::CodeInjection,
            "CWE-94",
        ),
        msg(
            "SSRF",
            r"(?i)\b(ssrf|server[-\s]side[-\s]request[-\s]forgery)\b",
            Severity::High,
            Category::WebSecurity,
            "CWE-918",
        ),
        msg(
            "Path Traversal",
            r"(?i)\b(path[-\s]traversal|directory[-\s]traversal|zip[-\s]slip)\b",
            Severity::High,
            Category::InputValidation,
            "CWE-22",
        ),
        msg(
            "XXE",
            r"(?i)\b(xxe|xml[-\s]external[-\s]entit)\b",
            Severity::High,
            Category::InputValidation,
            "CWE-611",
        ),
        msg(
            "Insecure Deserialization",
            r"(?i)\b(insecure[-\s]deserializ|object[-\s]injection|pop[-\s]chain|gadget[-\s]chain)\b",
            Severity::High,
            Category::CodeInjection,
            "CWE-502",
        ),
        msg(
            "Cross-Site Scripting",
            r"(?i)\b(xss|cross[-\s]site[-\s]scripting)\b",
            Severity::Medium,
            Category::WebSecurity,
            "CWE-79",
        ),
        msg(
            "Use After Free",
            r"(?i)\b(use[-\s]after[-\s]free|uaf|dangling[-\s]pointer)\b",
            Severity::Critical,
            Category::MemorySafety,
            "CWE-416",
        ),
        msg(
            "Buffer Overflow",
            r"(?i)\b(buffer[-\s]overflow|heap[-\s]overflow|stack[-\s]overflow)\b",
            Severity::Critical,
            Category::MemorySafety,
            "CWE-120",
        ),
        msg(
            "Out-of-Bounds Access",
            r"(?i)\b(out[-\s]of[-\s]bounds|\boob\b|index[-\s]out[-\s]of[-\s]range)\b",
            Severity::High,
            Category::MemorySafety,
            "CWE-787",
        ),
        msg(
            "Race Condition",
            r"(?i)\b(race[-\s]condition|data[-\s]race|toctou)\b",
            Severity::Medium,
            Category::Concurrency,
            "CWE-362",
        ),
        msg(
            "Double Free",
            r"(?i)\b(double[-\s]free|free[-\s]after[-\s]free)\b",
            Severity::High,
            Category::MemorySafety,
            "CWE-415",
        ),
        msg(
            "Type Confusion",
            r"(?i)\b(type[-\s]confusion)\b",
            Severity::High,
            Category::MemorySafety,
            "CWE-843",
        ),
        // ---- workerd / KJ C++ ruleset (gated to C/C++ files) ------------------
        workerd(
            "KJ Use After Move",
            r"(?i)\b(use[-\s]after[-\s]move|moved[-\s]value|kj::mv)\b",
            Severity::High,
            Category::MemorySafety,
            "CWE-416",
        ),
        workerd(
            "Lock Scope Issue",
            r"(?i)\b(lock[-\s]scope|lock[-\s]released|outside[-\s]lock|lock.*released.*use)\b",
            Severity::Medium,
            Category::Concurrency,
            "CWE-667",
        ),
        workerd(
            "Actor State Race",
            r"(?i)\b(actor[-\s]startup|concurrent[-\s]actor|toctou|check.*await.*init)\b",
            Severity::High,
            Category::Concurrency,
            "CWE-362",
        ),
        workerd(
            "GC Visitor Missing",
            r"(?i)\b(visitForGc|gc[-\s]visitor|missing[-\s]visitor)\b",
            Severity::Medium,
            Category::MemorySafety,
            "CWE-401",
        ),
        workerd(
            "Callback Self-Destruction",
            r"(?i)\b(this.*after|callback.*delete|self[-\s]destruct|abort.*drain)\b",
            Severity::Critical,
            Category::MemorySafety,
            "CWE-416",
        ),
        workerd(
            "Heap Corruption",
            r"(?i)\b(heap[-\s]corruption|heapArray|buffer[-\s]bounds|overrun)\b",
            Severity::High,
            Category::MemorySafety,
            "CWE-787",
        ),
        VulnerabilityPattern {
            lang_ext: cpp_exts(),
            ruleset: "workerd".to_string(),
            ..msg(
                "Static Without Const",
                r"(?i)\bstatic\s+(?!const)\b",
                Severity::Low,
                Category::Concurrency,
                "CWE-362",
            )
        },
        // ---- Diff-signature patterns (high signal; match added/removed lines) --
        // A fix that introduces an object-relation / ownership check is the
        // fingerprint of an IDOR/BOLA fix (e.g. the comments "Check comment
        // object" CVE).
        diff(
            "Added object-relation / ownership check",
            r#"(?im)^\+.*(getObjectId\(|getObjectType\(|isUserAccessible|canUser\w*See|->getOwner\(|getUserFolder\([^)]*\)->get|!==\s*\$this->|throw new (?:Forbidden|NotFound))"#,
            Severity::High,
            Category::AuthenticationAuthorization,
            "CWE-639",
        ),
        diff(
            "Added SSRF guard",
            r"(?im)^\+.*(allow_local_address|RemoteHostValidator|preventLocalAddress|isLocalAddress|dns_pinning)",
            Severity::High,
            Category::WebSecurity,
            "CWE-918",
        ),
        diff(
            "Added path-traversal guard",
            r#"(?im)^\+.*(basename\(|normalizePath|realpath\(|str_contains\([^,]*,\s*['"]\.\.|assertNotPathTraversal)"#,
            Severity::High,
            Category::InputValidation,
            "CWE-22",
        ),
        diff(
            "Added order-by / identifier whitelist (SQLi)",
            r#"(?im)^\+.*(in_array\(strtoupper|['"]ASC['"].*['"]DESC['"]|quoteColumnName)"#,
            Severity::Medium,
            Category::InputValidation,
            "CWE-89",
        ),
        diff(
            "Deserialization hardening",
            r"(?im)^\+.*(allowed_classes|unserialize\()",
            Severity::High,
            Category::CodeInjection,
            "CWE-502",
        ),
        diff(
            "XXE hardening",
            r"(?im)^\+.*(LIBXML_NOENT|disableEntityLoader|loadXML|external.entit)",
            Severity::High,
            Category::InputValidation,
            "CWE-611",
        ),
        // ---- Info-level corroboration (never dominates on its own) -----------
        // ---- autovuln ruleset: the classes the campaigns keep finding -------
        VulnerabilityPattern {
            // "prepared statement" and "parameterized query" are the fix, not
            // the bug: on workerd they matched 23 ordinary SQLite refactors.
            require_near: vec!["inject".into(), "escap".into(), "sanitiz".into()],
            ..autovuln(
                "SQL Injection",
                r"(?i)\b(sql[-\s]?inject\w*|sqli\b|unescaped\s+(?:identifier|table|column)|quote[-\s]?identifier)\b",
                Severity::Critical,
                Category::CodeInjection,
                "CWE-89",
            )
        },
        autovuln(
            "Missing Access-Control Check",
            r"(?i)\b(check_?can_|raise_for_access|access[-\s]?control\s+(?:check|callback)|permission\s+check|authoriz\w*\s+check|without\s+(?:checking|verifying)\s+permission)\b",
            Severity::Critical,
            Category::AuthenticationAuthorization,
            "CWE-862",
        ),
        autovuln(
            "Signature Verification Flaw",
            r"(?i)\b(signature\s+(?:not\s+)?verif\w*|verify\s+signature|trust\w*\s+(?:the\s+)?embedded\s+key|unverified\s+(?:jwt|jws|cose|token)|alg\s*[:=]\s*none|key\s+attestation)\b",
            Severity::Critical,
            Category::Cryptography,
            "CWE-347",
        ),
        autovuln(
            "Replay / Nonce Reuse",
            r"(?i)\b(replay[-\s]?attack|nonce\s+(?:reuse|not\s+checked|missing)|anti[-\s]?replay|proof[-\s]of[-\s]possession|c_?nonce|challenge\s+reuse)\b",
            Severity::High,
            Category::Cryptography,
            "CWE-294",
        ),
        autovuln(
            "Resource Exhaustion / DoS",
            // A bare "dos" matched "DOs", Cloudflare's own abbreviation for
            // Durable Objects, 30 times on workerd. Require the full phrase.
            r"(?i)\b(denial[-\s]of[-\s]service|dos\s+attack|quadratic\s+(?:time|behaviou?r)|decompression\s+bomb|unbounded\s+(?:alloc\w*|loop|recursion)|memory\s+exhaust\w*|zip\s+bomb)\b",
            Severity::High,
            Category::InputValidation,
            "CWE-400",
        ),
        autovuln(
            "Incorrect Calculation / Checker Soundness",
            r"(?i)\b(off[-\s]by[-\s]one|integer\s+(?:overflow|underflow)|incorrect\s+(?:bounds|offset|calculation)|stale\s+(?:offset|length|bounds)|unsound\w*|verifier\s+(?:accepts|bypass)|missing\s+(?:is64|width)\s+(?:gate|check))\b",
            Severity::Critical,
            Category::MemorySafety,
            "CWE-682",
        ),
        autovuln(
            "SSRF / Unvalidated URI",
            r"(?i)\b(ssrf|server[-\s]side[-\s]request[-\s]forgery|arbitrary\s+ur[il]|no\s+(?:scheme|host)\s+allow[-\s]?list|prefix\s+(?:check|validat)\w*\s+missing)\b",
            Severity::High,
            Category::WebSecurity,
            "CWE-918",
        ),
        // ---- OWASP Top 10 coverage ------------------------------------------
        // A02 Cryptographic Failures
        VulnerabilityPattern {
            // Naming a hash is not a vulnerability. A runtime that implements
            // WebCrypto mentions MD5 and SHA-1 as supported algorithms.
            require_near: vec![
                "weak".into(),
                "insecure".into(),
                "deprecat".into(),
                "collision".into(),
                "downgrade".into(),
                "forbid".into(),
            ],
            ..autovuln(
                "Weak Cryptography",
                r"(?i)\b(md5|sha-?1|rc4|3des|ecb\s+mode|weak\s+(?:cipher|hash|crypto)|insecure\s+(?:cipher|hash)|deprecated\s+(?:cipher|algorithm))\b",
                Severity::High,
                Category::Cryptography,
                "CWE-327",
            )
        },
        autovuln(
            "Insecure Randomness",
            r"(?i)\b(math\.random|non-?cryptographic\s+(?:rng|random)|threadlocalrandom|insecure\s+random|predictable\s+(?:token|seed|key|nonce)|weak\s+(?:prng|entropy)|\brandom\(\))\b",
            Severity::High,
            Category::Cryptography,
            "CWE-338",
        ),
        autovuln(
            "Hardcoded Secret",
            r"(?i)\b(hard-?coded\s+(?:secret|password|credential|key|token)|default\s+(?:password|credential|secret)|leaked\s+(?:secret|credential|api[-\s]?key)|secret\s+in\s+(?:source|repo|code))\b",
            Severity::Critical,
            Category::DataExposure,
            "CWE-798",
        ),
        // A03 Injection
        autovuln(
            "Template Injection",
            r"(?i)\b(server-?side\s+template\s+injection|\bssti\b|template\s+injection|jinja2?\s+(?:injection|sandbox\s+escape)|from_?string\s*\(\s*user)\b",
            Severity::Critical,
            Category::CodeInjection,
            "CWE-1336",
        ),
        autovuln(
            "NoSQL / LDAP Injection",
            r"(?i)\b(nosql\s+injection|mongo\s+injection|ldap\s+injection|\$where\s+injection|operator\s+injection)\b",
            Severity::High,
            Category::CodeInjection,
            "CWE-943",
        ),
        VulnerabilityPattern {
            // A JS runtime touches __proto__ constantly. Only a pollution
            // context makes it a finding.
            require_near: vec!["pollut".into(), "inject".into(), "sanitiz".into()],
            ..autovuln(
                "Prototype Pollution",
                r"(?i)\b(prototype\s+pollution|__proto__|constructor\.prototype\s+(?:pollution|assign))\b",
                Severity::High,
                Category::CodeInjection,
                "CWE-1321",
            )
        },
        // A01 Broken Access Control
        autovuln(
            "Open Redirect",
            r"(?i)\b(open\s+redirect|unvalidated\s+redirect|redirect\s+to\s+(?:user|attacker)-?(?:controlled|supplied))\b",
            Severity::Medium,
            Category::WebSecurity,
            "CWE-601",
        ),
        autovuln(
            "Mass Assignment",
            r"(?i)\b(mass\s+assignment|over-?posting|unfiltered\s+(?:bulk\s+)?assign\w*|allow_?list\s+of\s+fields)\b",
            Severity::High,
            Category::AuthenticationAuthorization,
            "CWE-915",
        ),
        // A05 Security Misconfiguration
        autovuln(
            "CORS Misconfiguration",
            r"(?i)\b(cors\s+(?:misconfig\w*|bypass)|access-control-allow-origin\s*[:=]\s*\*|allow-?credentials\s+with\s+wildcard|permissive\s+cors)\b",
            Severity::High,
            Category::WebSecurity,
            "CWE-942",
        ),
        autovuln(
            "Debug / Unsafe Default Enabled",
            r"(?i)\b(debug\s+(?:mode\s+)?enabled\s+in\s+prod|stack\s+trace\s+(?:exposed|leaked)|directory\s+listing|insecure\s+default|disabled\s+(?:by\s+default\s+)?(?:tls|verification|sandbox))\b",
            Severity::Medium,
            Category::WebSecurity,
            "CWE-16",
        ),
        // A07 Identification and Authentication Failures
        autovuln(
            "Authentication Failure",
            r"(?i)\b(session\s+fixation|missing\s+(?:auth\w*|mfa)|auth\w*\s+(?:bypass|missing)\s+on\s+endpoint|unauthenticated\s+(?:access|endpoint|rce)|jwt\s+(?:forg\w*|none\s+alg|signature\s+skip))\b",
            Severity::Critical,
            Category::AuthenticationAuthorization,
            "CWE-287",
        ),
        // A08 Software and Data Integrity Failures
        autovuln(
            "Supply-Chain / Integrity",
            r"(?i)\b(unsigned\s+(?:update|artifact|package)|supply[-\s]chain|integrity\s+check\s+(?:missing|bypass)|checksum\s+not\s+verified|pickle\s+(?:load|rce))\b",
            Severity::Critical,
            Category::CodeInjection,
            "CWE-494",
        ),
        // A09 Logging and Monitoring Failures
        autovuln(
            "Sensitive Data in Logs",
            r"(?i)\b(log\w*\s+(?:the\s+)?(?:password|secret|token|credential|api[-\s]?key)|sensitive\s+data\s+in\s+logs?|log\s+injection|redact\w*\s+(?:secret|token))\b",
            Severity::Medium,
            Category::DataExposure,
            "CWE-532",
        ),
        // A04 Insecure Design
        autovuln(
            "Missing Rate Limit",
            r"(?i)\b(rate[-\s]?limit\w*\s+(?:missing|bypass|absent)|no\s+rate[-\s]?limit|brute[-\s]?force\s+(?:possible|protection))\b",
            Severity::Medium,
            Category::WebSecurity,
            "CWE-770",
        ),
        autovuln(
            "TOCTOU",
            r"(?i)\b(toctou|time[-\s]of[-\s]check|check[-\s]then[-\s]use|re-?validate\s+after\s+check)\b",
            Severity::High,
            Category::Concurrency,
            "CWE-367",
        ),
        msg(
            "CVE Reference",
            r"(?i)\bcve[-\s]?(\d{4}[-\s]?\d{4,})\b",
            Severity::Info,
            Category::Generic,
            "",
        ),
        msg(
            "Security-fix marker",
            r"(?i)\b(fix\(security\)|security[-\s]fix|GHSA-|hackerone|advisory)\b",
            Severity::Info,
            Category::Generic,
            "",
        ),
        // Chromium's own trailer convention (`Bug: 123456`, `Fixed: 123456`),
        // present on essentially every Chromium/V8 commit and the most
        // reliable link from a finding back to its tracked bug.
        msg(
            "Chromium Bug Trailer",
            r"(?im)^(?:bug|fixed)\s*:\s*(\d{4,})\s*$",
            Severity::Info,
            Category::Generic,
            "",
        ),
        // The two URL forms Chromium has used for its public bug tracker:
        // legacy crbug.com short links, and the issues.chromium.org tracker
        // it migrated to (both also reachable via issuetracker.google.com).
        msg(
            "Chromium Bug Tracker URL",
            r"(?i)\b(?:crbug\.com/|issues\.chromium\.org/issues/|issuetracker\.google\.com/issues/)(\d{4,})\b",
            Severity::Info,
            Category::Generic,
            "",
        ),
    ];

    // ---- Context-gated weak crypto ------------------------------------------
    // Only flag md5/sha1/des/rc4 in a *security* context, and never when the
    // surrounding text points at a benign integrity/cache use.
    v.push(VulnerabilityPattern {
        name: "Weak Cryptography (security context)".to_string(),
        pattern: r"(?i)\b(md5|sha1|md4|\bdes\b|rc4|\becb\b)\b".to_string(),
        severity: Severity::Medium,
        category: Category::Cryptography,
        description: "Weak hash/cipher used in a security-sensitive context".to_string(),
        cwe: Some("CWE-327".to_string()),
        examples: Vec::new(),
        target: MatchTarget::Both,
        require_near: [
            "password",
            "passwd",
            "token",
            "secret",
            "hmac",
            "sign",
            "signature",
            "session",
            "csrf",
            "auth",
            "kdf",
            "salt",
            "credential",
            "cookie",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        suppress_near: [
            "content-md5",
            "etag",
            "checksum",
            "cache",
            "filecache",
            "integrity",
            "dedup",
            "uniqid",
            "cache_key",
            "cachekey",
            "content md5",
            "s3",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        lang_ext: Vec::new(),
        ruleset: String::new(),
    });

    v
}
