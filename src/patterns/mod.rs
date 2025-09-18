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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Category {
    MemorySafety,
    Cryptography,
    WebSecurity,
    InputValidation,
    AuthenticationAuthorization,
    Concurrency,
    DataExposure,
    CodeInjection,
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
}

pub fn default_patterns() -> Vec<VulnerabilityPattern> {
    vec![
        // Memory Safety Patterns
        VulnerabilityPattern {
            name: "Use After Free".to_string(),
            pattern: r"(?i)\b(use[-\s]after[-\s]free|uaf|dangling[-\s]pointer)\b".to_string(),
            severity: Severity::Critical,
            category: Category::MemorySafety,
            description: "Potential use-after-free vulnerability".to_string(),
            cwe: Some("CWE-416".to_string()),
            examples: vec!["Fix use after free".to_string(), "UAF vulnerability".to_string()],
        },
        VulnerabilityPattern {
            name: "Buffer Overflow".to_string(),
            pattern: r"(?i)\b(buffer[-\s]overflow|stack[-\s]overflow|heap[-\s]overflow|bof|ovflw|StackO)\b".to_string(),
            severity: Severity::Critical,
            category: Category::MemorySafety,
            description: "Potential buffer overflow vulnerability".to_string(),
            cwe: Some("CWE-120".to_string()),
            examples: vec!["Fix buffer overflow".to_string(), "Stack overflow protection".to_string()],
        },
        VulnerabilityPattern {
            name: "Double Free".to_string(),
            pattern: r"(?i)\b(double[-\s]free|free[-\s]after[-\s]free)\b".to_string(),
            severity: Severity::High,
            category: Category::MemorySafety,
            description: "Potential double-free vulnerability".to_string(),
            cwe: Some("CWE-415".to_string()),
            examples: vec!["Fix double free".to_string()],
        },
        VulnerabilityPattern {
            name: "Race Condition".to_string(),
            pattern: r"(?i)\b(race[-\s]condition|data[-\s]race|concurrency[-\s]bug)\b".to_string(),
            severity: Severity::High,
            category: Category::Concurrency,
            description: "Potential race condition vulnerability".to_string(),
            cwe: Some("CWE-362".to_string()),
            examples: vec!["Fix race condition".to_string()],
        },
        VulnerabilityPattern {
            name: "Memory Leak".to_string(),
            pattern: r"(?i)\b(memory[-\s]leak|mem[-\s]leak|resource[-\s]leak)\b".to_string(),
            severity: Severity::Medium,
            category: Category::MemorySafety,
            description: "Potential memory leak".to_string(),
            cwe: Some("CWE-401".to_string()),
            examples: vec!["Fix memory leak".to_string()],
        },
        VulnerabilityPattern {
            name: "Null Pointer Dereference".to_string(),
            pattern: r"(?i)\b(null[-\s]pointer|nullptr[-\s]dereference|segfault|sigsegv)\b".to_string(),
            severity: Severity::Medium,
            category: Category::MemorySafety,
            description: "Potential null pointer dereference".to_string(),
            cwe: Some("CWE-476".to_string()),
            examples: vec!["Fix null pointer".to_string(), "Segmentation fault".to_string()],
        },

        // Security Patterns
        VulnerabilityPattern {
            name: "Code Injection".to_string(),
            pattern: r"(?i)\b(code[-\s]injection|command[-\s]injection|sql[-\s]injection|remote[-\s]code[-\s]execution|rce)\b".to_string(),
            severity: Severity::Critical,
            category: Category::CodeInjection,
            description: "Potential code injection vulnerability".to_string(),
            cwe: Some("CWE-94".to_string()),
            examples: vec!["Fix code injection".to_string(), "SQL injection".to_string()],
        },

        // Type confusion
        VulnerabilityPattern {
            name: "Type confusion".to_string(),
            pattern: r"(?i)\b(type confusion|confused)\b".to_string(),
            severity: Severity::Critical,
            category: Category::CodeInjection,
            description: "Access of Resource Using Incompatible Type ('Type Confusion')".to_string(),
            cwe: Some("CWE-843".to_string()),
            examples: vec!["Fix code injection".to_string(), "Type confusion".to_string()],
        },
        VulnerabilityPattern {
            name: "Authentication Bypass".to_string(),
            pattern: r"(?i)\b(auth[-\s]bypass|authentication[-\s]bypass|privilege[-\s]escalation)\b".to_string(),
            severity: Severity::Critical,
            category: Category::AuthenticationAuthorization,
            description: "Potential authentication bypass".to_string(),
            cwe: Some("CWE-287".to_string()),
            examples: vec!["Fix auth bypass".to_string()],
        },
        VulnerabilityPattern {
            name: "Cross-Site Scripting".to_string(),
            pattern: r"(?i)\b(xss|cross[-\s]site[-\s]scripting)\b".to_string(),
            severity: Severity::Medium,
            category: Category::WebSecurity,
            description: "Potential XSS vulnerability".to_string(),
            cwe: Some("CWE-79".to_string()),
            examples: vec!["Fix XSS".to_string()],
        },

        // Crypto Patterns
        VulnerabilityPattern {
            name: "Weak Cryptography".to_string(),
            pattern: r"(?i)\b(weak[-\s]crypto|weak[-\s]cipher|broken[-\s]crypto|md5|sha1\b|des\b|rc4)\b".to_string(),
            severity: Severity::Medium,
            category: Category::Cryptography,
            description: "Weak cryptographic implementation".to_string(),
            cwe: Some("CWE-327".to_string()),
            examples: vec!["Replace weak crypto".to_string()],
        },

        // Generic Security
        VulnerabilityPattern {
            name: "CVE Reference".to_string(),
            pattern: r"(?i)\bcve[-\s]?(\d{4}[-\s]?\d{4,})\b".to_string(),
            severity: Severity::Info,
            category: Category::Generic,
            description: "CVE reference found".to_string(),
            cwe: None,
            examples: vec!["CVE-2021-1234".to_string()],
        },
        VulnerabilityPattern {
            name: "Security Fix".to_string(),
            pattern: r"(?i)\b(security[-\s]fix|security[-\s]patch|vulnerability|exploit|malicious|vulnerable|fallthrough)\b".to_string(),
            severity: Severity::Info,
            category: Category::Generic,
            description: "General security-related change".to_string(),
            cwe: None,
            examples: vec!["Security fix".to_string()],
        },
    ]
}
