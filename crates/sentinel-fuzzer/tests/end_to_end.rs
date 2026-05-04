//! End-to-end integration test: Sentinel against the synthetic-crash fixture.
//!
//! This is the **critical regression test** the engineering review called out
//! as a Week 3 hard requirement. Without it, the fuzzer can silently regress
//! to "swallows all crashes" and Week 5 dogfooding finds nothing on MoodBloom
//! because the integration is broken — but no test would alert us.
//!
//! What it verifies:
//!
//! 1. `discover_targets` finds the synthetic `store_mood` target.
//! 2. Feeding the canned libFuzzer stderr through the parse + finding
//!    pipeline produces exactly one finding.
//! 3. The finding has severity `High`, kind tag `panic`, the right
//!    location, and a stable id of the form `fuzzer.crash.panic.<hash>`.
//! 4. The finding's description includes a reproduction command.
//!
//! It does NOT actually invoke `cargo fuzz` — that requires a nightly
//! toolchain that CI on stable doesn't have. A separate
//! `#[ignore]`d test (`live_synthetic_crash`) does the real run for local
//! dogfooding.

use std::path::PathBuf;

use sentinel_core::{Severity, Tool};
use sentinel_fuzzer::{crash_to_finding, dedup_findings, discover_targets, outcome_from_captured};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("synthetic_crash")
}

#[test]
fn discovers_synthetic_target() {
    let targets = discover_targets(&fixture_root()).expect("discover");
    let names: Vec<&str> = targets.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["store_mood"],
        "expected one target named store_mood"
    );
}

#[test]
fn pipeline_emits_one_high_severity_panic_finding() {
    let stderr = std::fs::read_to_string(fixture_root().join("fuzz").join("expected_stderr.txt"))
        .expect("read expected_stderr.txt");

    let outcome = outcome_from_captured(stderr, vec![]);
    assert!(
        !outcome.clean,
        "outcome should not be clean — stderr fixture contains a panic"
    );
    assert_eq!(outcome.crashes.len(), 1, "exactly one crash expected");

    let crash = &outcome.crashes[0];
    assert_eq!(
        crash.summary, "synthetic panic for sentinel integration test",
        "panic message should be parsed verbatim"
    );

    let findings: Vec<_> = outcome
        .crashes
        .iter()
        .map(|c| crash_to_finding("store_mood", c))
        .collect();
    let findings = dedup_findings(findings);
    assert_eq!(findings.len(), 1, "one crash should yield one finding");

    let f = &findings[0];
    assert_eq!(f.severity, Severity::High, "panic in IPC handler is High");
    assert_eq!(f.tool, Tool::Fuzzer);
    assert_eq!(f.component, "fuzz_target:store_mood");
    assert!(
        f.id.starts_with("fuzzer.crash.panic."),
        "id should be namespaced under fuzzer.crash.panic.*, got {}",
        f.id
    );
    let loc = f
        .location
        .as_ref()
        .expect("location parsed from panic line");
    assert_eq!(loc.file, "fuzz_targets/store_mood.rs");
    assert_eq!(loc.line, Some(18));
    assert!(
        f.description.contains("cargo +nightly fuzz run store_mood"),
        "description should include reproduce command"
    );
    assert!(
        f.description
            .contains("./crash-c0ffee123456789abcdef0123456789abcdef01"),
        "description should include the artifact path for reproducibility"
    );
}

#[test]
fn finding_id_is_stable_across_runs() {
    // Same input twice should produce same id — proves dedup hash is deterministic.
    let stderr = std::fs::read_to_string(fixture_root().join("fuzz").join("expected_stderr.txt"))
        .expect("read fixture");
    let id1 = {
        let outcome = outcome_from_captured(stderr.clone(), vec![]);
        crash_to_finding("store_mood", &outcome.crashes[0]).id
    };
    let id2 = {
        let outcome = outcome_from_captured(stderr, vec![]);
        crash_to_finding("store_mood", &outcome.crashes[0]).id
    };
    assert_eq!(
        id1, id2,
        "finding ids must be deterministic for stable dedup"
    );
}

#[test]
#[ignore = "requires cargo-fuzz + nightly; run manually with `cargo test -- --ignored`"]
fn live_synthetic_crash() {
    use sentinel_fuzzer::{cargo_fuzz_available, run_target, RunOptions};
    use std::time::Duration;

    if !cargo_fuzz_available() {
        eprintln!("cargo-fuzz not installed; skipping live run");
        return;
    }

    // This test only works against a real, buildable fuzz crate. The fixture
    // shipped here is a directory-shape stub. Local dogfooding should
    // duplicate the fixture into a scratch project that links libfuzzer-sys
    // and run this test against that project.
    let project = std::env::var("SENTINEL_LIVE_FUZZ_PROJECT")
        .map(PathBuf::from)
        .expect("set SENTINEL_LIVE_FUZZ_PROJECT to a path with a buildable fuzz crate");

    let opts = RunOptions {
        project_root: project,
        target: "store_mood".to_string(),
        duration: Duration::from_secs(15),
        timeout_secs: 5,
        rss_limit_mb: 1024,
        seed: Some(42),
        skip_command: false,
    };
    let outcome = run_target(&opts).expect("live fuzz run");
    assert!(!outcome.clean, "synthetic target should crash within 15s");
    assert!(!outcome.crashes.is_empty(), "expected at least one crash");
}
