//! Shared domain types for the Sentinel security auditor.
//!
//! This crate defines the data model that the cartographer, fuzzer and
//! analyzer crates emit and that the report generator consumes. Keeping
//! these types in one place lets the tools compose into a unified report
//! without depending on each other directly.

#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

pub mod io;
pub mod scan;

/// Severity rating for a security finding, ordered from least to most severe.
///
/// Use `PartialOrd`/`Ord` to sort or filter findings: `Severity::Critical`
/// compares greater than `Severity::High`, and so on.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational; no security risk but worth knowing.
    Info,
    /// Low severity — minor risk or hardening opportunity.
    Low,
    /// Medium severity — exploitable under specific conditions.
    Medium,
    /// High severity — readily exploitable or sensitive data exposure.
    High,
    /// Critical severity — remote unauthenticated impact or full compromise.
    Critical,
}

impl Severity {
    /// Numeric rank for ordering (higher = more severe).
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        f.write_str(s)
    }
}

/// Which Sentinel tool produced a finding.
///
/// Helps consumers route findings to the right remediation guidance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    /// Dependency / attack-surface cartographer.
    Cartographer,
    /// IPC behavioral fuzzer.
    Fuzzer,
    /// Static pattern analyzer.
    Analyzer,
}

impl fmt::Display for Tool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Tool::Cartographer => "cartographer",
            Tool::Fuzzer => "fuzzer",
            Tool::Analyzer => "analyzer",
        };
        f.write_str(s)
    }
}

/// Optional source location attached to a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Location {
    /// Path to the file, relative to the scan root when possible.
    pub file: String,
    /// 1-indexed line number, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

impl Location {
    /// Construct a `Location` from a path and optional line number.
    #[must_use]
    pub fn new<S: Into<String>>(file: S, line: Option<u32>) -> Self {
        Self {
            file: file.into(),
            line,
        }
    }
}

/// A single security finding emitted by one of the Sentinel tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    /// Stable machine-readable identifier (e.g. `cartographer.cve.RUSTSEC-2024-0001`).
    pub id: String,
    /// Short human-readable title.
    pub title: String,
    /// Long-form description suitable for a report body.
    pub description: String,
    /// Severity rating.
    pub severity: Severity,
    /// Which tool produced this finding.
    pub tool: Tool,
    /// Logical component this finding pertains to (crate name, file, command, etc.).
    pub component: String,
    /// Concrete remediation suggestion for the user.
    pub suggestion: String,
    /// Optional source location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// Free-form references (CVE links, RUSTSEC ids, OWASP entries, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

/// Aggregate counts across all findings in a [`Report`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanSummary {
    /// Total findings across all severities.
    pub total: usize,
    /// Number of `Critical` findings.
    pub critical: usize,
    /// Number of `High` findings.
    pub high: usize,
    /// Number of `Medium` findings.
    pub medium: usize,
    /// Number of `Low` findings.
    pub low: usize,
    /// Number of `Info` findings.
    pub info: usize,
}

impl ScanSummary {
    /// Compute a summary from a slice of findings.
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Self::default();
        for f in findings {
            s.total += 1;
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
                Severity::Info => s.info += 1,
            }
        }
        s
    }
}

/// Top-level scan report combining findings from one or more tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    /// Project / app name (best-effort, from `Cargo.toml` or `tauri.conf.json`).
    pub app_name: String,
    /// Absolute path of the scanned project root.
    pub scan_root: String,
    /// UTC timestamp when the scan started.
    pub scan_date: DateTime<Utc>,
    /// Sentinel version string that produced this report.
    pub sentinel_version: String,
    /// All findings, in arbitrary order. Use `summary` for counts.
    pub findings: Vec<Finding>,
    /// Pre-computed counts.
    pub summary: ScanSummary,
}

impl Report {
    /// Build a report and compute the summary in one step.
    #[must_use]
    pub fn new(
        app_name: impl Into<String>,
        scan_root: impl Into<String>,
        findings: Vec<Finding>,
    ) -> Self {
        let summary = ScanSummary::from_findings(&findings);
        Self {
            app_name: app_name.into(),
            scan_root: scan_root.into(),
            scan_date: Utc::now(),
            sentinel_version: env!("CARGO_PKG_VERSION").to_string(),
            findings,
            summary,
        }
    }

    /// Sort findings in-place by severity (highest first) and then by id.
    pub fn sort_findings(&mut self) {
        self.findings
            .sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, severity: Severity) -> Finding {
        Finding {
            id: id.to_string(),
            title: id.to_string(),
            description: String::new(),
            severity,
            tool: Tool::Cartographer,
            component: String::new(),
            suggestion: String::new(),
            location: None,
            references: vec![],
        }
    }

    #[test]
    fn severity_ordering_is_low_to_high() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn summary_counts_each_severity() {
        let findings = vec![
            finding("a", Severity::Critical),
            finding("b", Severity::Critical),
            finding("c", Severity::High),
            finding("d", Severity::Medium),
            finding("e", Severity::Low),
            finding("f", Severity::Info),
            finding("g", Severity::Info),
        ];
        let s = ScanSummary::from_findings(&findings);
        assert_eq!(s.total, 7);
        assert_eq!(s.critical, 2);
        assert_eq!(s.high, 1);
        assert_eq!(s.medium, 1);
        assert_eq!(s.low, 1);
        assert_eq!(s.info, 2);
    }

    #[test]
    fn report_new_computes_summary() {
        let r = Report::new(
            "demo",
            "/tmp/demo",
            vec![finding("x", Severity::High), finding("y", Severity::Low)],
        );
        assert_eq!(r.app_name, "demo");
        assert_eq!(r.summary.total, 2);
        assert_eq!(r.summary.high, 1);
        assert_eq!(r.summary.low, 1);
    }

    #[test]
    fn sort_findings_orders_by_severity_desc_then_id_asc() {
        let mut r = Report::new(
            "demo",
            "/tmp/demo",
            vec![
                finding("low-b", Severity::Low),
                finding("crit-a", Severity::Critical),
                finding("low-a", Severity::Low),
                finding("crit-b", Severity::Critical),
            ],
        );
        r.sort_findings();
        let ids: Vec<_> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["crit-a", "crit-b", "low-a", "low-b"]);
    }

    #[test]
    fn severity_serializes_lowercase() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");
    }

    #[test]
    fn finding_roundtrips_through_json() {
        let original = Finding {
            id: "test.1".to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            severity: Severity::High,
            tool: Tool::Analyzer,
            component: "src/main.rs".to_string(),
            suggestion: "fix it".to_string(),
            location: Some(Location::new("src/main.rs", Some(42))),
            references: vec!["https://example.com".to_string()],
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }
}
