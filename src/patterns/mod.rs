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
    /// Number of commits (across branches) sharing this fix. 1 for a normal
    /// commit; >1 when the same fix was backported — a strong CVE signal.
    #[serde(default = "one")]
    pub backport_count: usize,
    /// Capped changed-lines diff snippet for downstream triage.
    #[serde(default)]
    pub diff_snippet: String,
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
