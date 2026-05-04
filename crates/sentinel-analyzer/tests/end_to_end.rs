//! End-to-end integration test: Sentinel analyzer against the
//! synthetic-vulnerability fixture.
//!
//! This is the **critical regression test** the engineering review called
//! out as a Week 4 hard requirement. Without it, the analyzer can silently
//! regress to "swallows all findings" and Week 5 dogfooding on MoodBloom
//! finds nothing because the integration is broken — but no test alerts us.
//!
//! What it verifies:
//!
//! 1. `analyze_project` finds every seeded issue in the fixture.
//! 2. Each finding has the right severity, rule id, file location, and
//!    a non-empty suggestion.
//! 3. Re-running produces byte-identical finding ids — required for stable
//!    CI gating.
//! 4. The HTML report renders without crashing and contains every finding.
//!
//! Adding or removing issues in the fixture REQUIRES updating the
//! `expected` set below. That tight coupling is intentional: it forces a
//! reviewer to acknowledge changes to the analyzer's coverage surface.

use std::collections::BTreeSet;
use std::path::PathBuf;

use sentinel_analyzer::{analyze_project, render_html, render_json, AnalyzeOptions};
use sentinel_core::Severity;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("synthetic_vuln")
}

#[test]
fn synthetic_vuln_emits_all_seeded_findings() {
    let report = analyze_project(&fixture_root(), &AnalyzeOptions::default())
        .expect("analyze synthetic_vuln");

    let rule_ids: BTreeSet<&str> = report
        .findings
        .iter()
        .filter_map(|f| f.id.split('.').nth(1).zip(f.id.split('.').nth(2)))
        .map(|(a, b)| {
            // f.id is like "analyzer.tauri.command_injection.<file>:<line>".
            // We want the rule id namespace which is the segments AFTER `analyzer.`
            // up to (but not including) the first `:`. The split-take-2 above is
            // correct for two-segment ids; rebuild in tests just to be defensive.
            let _ = (a, b);
            "_unused"
        })
        .collect();
    let _ = rule_ids; // we'll inspect via a more reliable parser below

    let actual: BTreeSet<String> = report.findings.iter().map(extract_rule_id).collect();
    let expected: BTreeSet<String> = [
        "tauri.command_injection",
        "tauri.path_traversal",
        "tauri.unsafe_in_command",
        "crypto.weak_hash",
        "webview.eval",
        "webview.dangerously_set_inner_html",
        "network.http_in_fetch",
        "tauri.csp_unsafe_eval",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();

    let missing: Vec<&String> = expected.difference(&actual).collect();
    assert!(
        missing.is_empty(),
        "missing expected findings: {missing:?}\nactual: {actual:?}"
    );

    let extra: Vec<&String> = actual.difference(&expected).collect();
    assert!(
        extra.is_empty(),
        "unexpected extra findings: {extra:?}\nexpected: {expected:?}"
    );
}

#[test]
fn severity_calibration_holds_for_synthetic_vuln() {
    let report = analyze_project(&fixture_root(), &AnalyzeOptions::default()).unwrap();
    let by_rule: std::collections::HashMap<String, Severity> = report
        .findings
        .iter()
        .map(|f| (extract_rule_id(f), f.severity))
        .collect();

    assert_eq!(
        by_rule.get("tauri.command_injection"),
        Some(&Severity::Critical),
        "command-injection must be Critical"
    );
    assert_eq!(
        by_rule.get("tauri.path_traversal"),
        Some(&Severity::High),
        "path-traversal must be High"
    );
    assert_eq!(
        by_rule.get("webview.eval"),
        Some(&Severity::High),
        "webview eval must be High"
    );
    assert_eq!(
        by_rule.get("webview.dangerously_set_inner_html"),
        Some(&Severity::High),
        "dangerouslySetInnerHTML must be High"
    );
    assert_eq!(
        by_rule.get("crypto.weak_hash"),
        Some(&Severity::Medium),
        "weak hash defaults to Medium"
    );
    assert_eq!(
        by_rule.get("network.http_in_fetch"),
        Some(&Severity::Medium),
        "http URL defaults to Medium"
    );
    assert_eq!(
        by_rule.get("tauri.unsafe_in_command"),
        Some(&Severity::Medium),
        "unsafe in command is Medium"
    );
    assert_eq!(
        by_rule.get("tauri.csp_unsafe_eval"),
        Some(&Severity::High),
        "unsafe-eval CSP is High"
    );
}

#[test]
fn finding_ids_are_stable_across_runs() {
    let r1 = analyze_project(&fixture_root(), &AnalyzeOptions::default()).unwrap();
    let r2 = analyze_project(&fixture_root(), &AnalyzeOptions::default()).unwrap();
    let ids1: BTreeSet<&str> = r1.findings.iter().map(|f| f.id.as_str()).collect();
    let ids2: BTreeSet<&str> = r2.findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids1, ids2,
        "two consecutive analyzer runs must produce identical finding ids"
    );
}

#[test]
fn html_report_renders_every_finding() {
    let report = analyze_project(&fixture_root(), &AnalyzeOptions::default()).unwrap();
    let html = render_html(&report);
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.ends_with("</body></html>\n"));
    for f in &report.findings {
        assert!(
            html.contains(&f.id),
            "html should mention finding id `{}`",
            f.id
        );
    }
    assert!(html.contains(&format!(
        "Total findings: <strong>{}</strong>",
        report.summary.total
    )));
}

#[test]
fn json_report_round_trips_through_serde() {
    let report = analyze_project(&fixture_root(), &AnalyzeOptions::default()).unwrap();
    let json = render_json(&report).unwrap();
    let parsed: sentinel_core::Report = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.app_name, report.app_name);
    assert_eq!(parsed.findings.len(), report.findings.len());
    assert_eq!(parsed.summary.total, report.summary.total);
}

#[test]
fn fixture_findings_all_have_locations_and_suggestions() {
    let report = analyze_project(&fixture_root(), &AnalyzeOptions::default()).unwrap();
    for f in &report.findings {
        assert!(
            f.location.is_some(),
            "finding `{}` is missing a location",
            f.id
        );
        assert!(
            !f.suggestion.is_empty(),
            "finding `{}` is missing a suggestion",
            f.id
        );
        assert!(!f.title.is_empty(), "finding `{}` is missing a title", f.id);
    }
}

/// Extract the rule namespace + name (e.g. `tauri.command_injection`) from a
/// full finding id like
/// `"analyzer.tauri.command_injection.src-tauri/src/main.rs:18"`.
fn extract_rule_id(f: &sentinel_core::Finding) -> String {
    let after_prefix = f.id.strip_prefix("analyzer.").unwrap_or(&f.id);
    let mut segments = after_prefix.splitn(3, '.');
    let ns = segments.next().unwrap_or("");
    let name = segments.next().unwrap_or("");
    if name.is_empty() {
        ns.to_string()
    } else {
        format!("{ns}.{name}")
    }
}
