//! Integration tests that drive the unified CLI binary itself.
//!
//! These complement the in-process tests in `src/scan.rs` by exercising
//! the full clap argument-parsing + subprocess output path that real users
//! hit.

use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    // Cargo sets `CARGO_BIN_EXE_<name>` for every binary in the workspace.
    PathBuf::from(env!("CARGO_BIN_EXE_sentinel"))
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("sentinel-analyzer")
        .join("tests")
        .join("fixtures")
        .join("synthetic_vuln")
}

#[test]
fn version_flag_prints_version() {
    let out = Command::new(binary_path())
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sentinel"), "got: {stdout}");
}

#[test]
fn help_lists_scan_and_doctor_subcommands() {
    let out = Command::new(binary_path()).arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("scan"),
        "help should mention scan: {stdout}"
    );
    assert!(
        stdout.contains("doctor"),
        "help should mention doctor: {stdout}"
    );
}

#[test]
fn doctor_subcommand_runs_and_describes_each_dependency() {
    let out = Command::new(binary_path()).arg("doctor").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // doctor exits 2 when something is missing — we don't care which way it
    // goes here, only that the labels appear.
    for label in ["rustc", "cargo", "cargo-fuzz", "nightly toolchain", "tar"] {
        assert!(
            stdout.contains(label),
            "doctor missing `{label}` in output: {stdout}"
        );
    }
}

#[test]
fn scan_text_output_lists_critical_finding_first() {
    // `--no-advisories` keeps the test offline.
    let out = Command::new(binary_path())
        .arg("scan")
        .arg(fixture_root())
        .arg("--no-advisories")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // We don't assert on exit code: scan exits non-zero when High+ findings
    // appear, which is the expected behaviour against synthetic_vuln.
    assert!(
        stdout.contains("Sentinel v"),
        "expected report header, got: {stdout}"
    );
    // The critical finding (command-injection) should print before any High.
    let crit_pos = stdout
        .find("[CRITICAL]")
        .expect("expected at least one CRITICAL finding");
    let high_pos = stdout
        .find("[    HIGH]")
        .expect("expected at least one HIGH finding");
    assert!(
        crit_pos < high_pos,
        "CRITICAL should be reported before HIGH: crit_pos={crit_pos} high_pos={high_pos}"
    );
}

#[test]
fn scan_json_output_is_valid_serde() {
    let out = Command::new(binary_path())
        .arg("scan")
        .arg(fixture_root())
        .arg("--no-advisories")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("--format json should produce valid JSON: {e}\noutput:\n{stdout}")
    });
    assert!(
        parsed.get("findings").is_some(),
        "json missing 'findings' key"
    );
    assert!(
        parsed.get("summary").is_some(),
        "json missing 'summary' key"
    );
}

#[test]
fn scan_with_no_cartographer_and_no_analyzer_produces_empty_report() {
    let out = Command::new(binary_path())
        .arg("scan")
        .arg(fixture_root())
        .arg("--no-cartographer")
        .arg("--no-analyzer")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "exit should be 0 with no high+ findings"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let total = parsed["summary"]["total"].as_u64().unwrap();
    assert_eq!(total, 0, "expected zero findings when both tools skipped");
}

#[test]
fn scan_writes_to_output_file_when_o_flag_given() {
    let tmp = tempfile::tempdir().unwrap();
    let report_path = tmp.path().join("report.json");
    let out = Command::new(binary_path())
        .arg("scan")
        .arg(fixture_root())
        .arg("--no-advisories")
        .arg("--format")
        .arg("json")
        .arg("-o")
        .arg(&report_path)
        .output()
        .unwrap();
    let _ = out;
    let written = std::fs::read_to_string(&report_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert!(parsed["findings"].as_array().unwrap().len() >= 8);
}

#[test]
fn scan_html_format_emits_self_contained_html() {
    let out = Command::new(binary_path())
        .arg("scan")
        .arg(fixture_root())
        .arg("--no-advisories")
        .arg("--format")
        .arg("html")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("<!DOCTYPE html>"));
    assert!(stdout.contains("<style>")); // embedded CSS, not <link>
    assert!(!stdout.contains("<link "));
    assert!(stdout.contains("</body>"));
}
