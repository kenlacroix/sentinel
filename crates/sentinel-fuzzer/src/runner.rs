//! Drive `cargo fuzz run` and turn its output into a [`RunOutcome`].
//!
//! ## Toolchain assumptions
//!
//! - The user has `cargo-fuzz` installed (`cargo install cargo-fuzz`).
//! - The user has a recent nightly toolchain available (`rustup toolchain
//!   install nightly`). cargo-fuzz invokes nightly under the hood.
//!
//! When either is missing, we surface a clear install hint rather than a
//! cryptic process-spawn failure.
//!
//! ## What we run
//!
//! ```text
//! cargo +nightly fuzz run <target> -- \
//!   -max_total_time=<duration_secs> \
//!   -timeout=<per_input_timeout_secs> \
//!   -rss_limit_mb=<rss_limit>
//! ```
//!
//! libFuzzer exits non-zero on the first crash. We capture stderr, collect
//! any artifacts that appeared in `<project>/fuzz/artifacts/<target>/` since
//! the run started, and let the parser turn them into findings.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::discovery::{artifacts_dir, fuzz_crate_root};
use crate::parse::{parse_libfuzzer_stderr, CrashInfo};

/// Options controlling a single fuzz-run invocation.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Project root (the directory containing `fuzz/`).
    pub project_root: PathBuf,
    /// Fuzz target name.
    pub target: String,
    /// Total wall-clock duration to fuzz for.
    pub duration: Duration,
    /// Per-input timeout in seconds. Defaults to 25.
    pub timeout_secs: u32,
    /// Per-process RSS limit in MB. Defaults to 2048.
    pub rss_limit_mb: u32,
    /// Optional libFuzzer seed for reproducibility.
    pub seed: Option<u64>,
    /// Set to `true` to bypass the `cargo-fuzz` invocation entirely. Used by
    /// tests that exercise the artifact-collection path with a stubbed
    /// stderr/artifact pair, without requiring a nightly toolchain.
    pub skip_command: bool,
}

impl RunOptions {
    /// Convenience constructor with sensible defaults.
    #[must_use]
    pub fn new(
        project_root: impl Into<PathBuf>,
        target: impl Into<String>,
        duration: Duration,
    ) -> Self {
        Self {
            project_root: project_root.into(),
            target: target.into(),
            duration,
            timeout_secs: 25,
            rss_limit_mb: 2048,
            seed: None,
            skip_command: false,
        }
    }
}

/// Result of one fuzz-run invocation.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// Crash info parsed from stderr, if libFuzzer reported one.
    pub crashes: Vec<CrashInfo>,
    /// Full stderr captured from the process.
    pub stderr: String,
    /// New artifacts (paths) that appeared during the run.
    pub new_artifacts: Vec<PathBuf>,
    /// Whether `cargo fuzz` completed cleanly (no crashes, exit 0).
    pub clean: bool,
}

/// Toolchain probe — checks whether `cargo-fuzz` is on `$PATH`.
#[must_use]
pub fn cargo_fuzz_available() -> bool {
    Command::new("cargo")
        .arg("fuzz")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Run `cargo fuzz run <target>` once, observe artifacts, parse stderr.
///
/// # Errors
///
/// Returns an error if the project layout is invalid (no `fuzz/` directory)
/// or the cargo-fuzz binary cannot be executed at all. Crashes themselves
/// are *not* errors — a fuzz run that finds a crash is a successful run with
/// `RunOutcome { clean: false, crashes: [..] }`.
pub fn run_target(opts: &RunOptions) -> Result<RunOutcome> {
    let fuzz_root = fuzz_crate_root(&opts.project_root);
    if !fuzz_root.is_dir() {
        anyhow::bail!(
            "no fuzz/ subcrate at {}; run `cargo fuzz init` from the project root first",
            fuzz_root.display()
        );
    }

    let artifact_dir = artifacts_dir(&opts.project_root, &opts.target);
    let before = list_artifacts(&artifact_dir);

    let stderr = if opts.skip_command {
        String::new()
    } else {
        spawn_cargo_fuzz(opts, &fuzz_root)?
    };

    let after = list_artifacts(&artifact_dir);
    let new_artifacts: Vec<PathBuf> = after.difference(&before).cloned().collect();

    let mut crashes = Vec::new();
    if let Some(info) = parse_libfuzzer_stderr(&stderr) {
        crashes.push(info);
    }

    let clean = crashes.is_empty();
    Ok(RunOutcome {
        crashes,
        stderr,
        new_artifacts,
        clean,
    })
}

/// Compose a [`RunOutcome`] from a captured stderr blob and a set of
/// artifact paths. Used by tests and the synthetic-crash fixture to drive
/// the parsing / dedup pipeline without invoking cargo-fuzz.
#[must_use]
pub fn outcome_from_captured(stderr: String, new_artifacts: Vec<PathBuf>) -> RunOutcome {
    let mut crashes = Vec::new();
    if let Some(info) = parse_libfuzzer_stderr(&stderr) {
        crashes.push(info);
    }
    let clean = crashes.is_empty();
    RunOutcome {
        crashes,
        stderr,
        new_artifacts,
        clean,
    }
}

fn spawn_cargo_fuzz(opts: &RunOptions, fuzz_root: &Path) -> Result<String> {
    if !cargo_fuzz_available() {
        anyhow::bail!(
            "cargo-fuzz is not installed. Run:\n  cargo install cargo-fuzz\n\
             Sentinel also requires a nightly toolchain:\n  rustup toolchain install nightly"
        );
    }

    let mut cmd = Command::new("cargo");
    cmd.arg("+nightly").arg("fuzz").arg("run").arg(&opts.target);
    cmd.current_dir(fuzz_root);
    cmd.arg("--");
    cmd.arg(format!("-max_total_time={}", opts.duration.as_secs()));
    cmd.arg(format!("-timeout={}", opts.timeout_secs));
    cmd.arg(format!("-rss_limit_mb={}", opts.rss_limit_mb));
    if let Some(seed) = opts.seed {
        cmd.arg(format!("-seed={seed}"));
    }
    // Always-on hardening: keep going through caught panics so libFuzzer
    // emits a final SUMMARY even when the harness panics deterministically.
    cmd.env("RUST_BACKTRACE", "1");

    let output = cmd
        .output()
        .with_context(|| format!("failed to spawn `cargo +nightly fuzz run {}`", opts.target))?;
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

fn list_artifacts(dir: &Path) -> HashSet<PathBuf> {
    let mut out = HashSet::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|t| t.is_file()) {
            out.insert(entry.path());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_target_errors_without_fuzz_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = RunOptions::new(tmp.path(), "x", Duration::from_secs(1));
        let err = run_target(&opts).unwrap_err();
        assert!(err.to_string().contains("no fuzz/ subcrate"));
    }

    #[test]
    fn run_target_with_skip_command_returns_clean_when_stderr_empty() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("fuzz").join("fuzz_targets")).unwrap();
        let mut opts = RunOptions::new(tmp.path(), "x", Duration::from_secs(1));
        opts.skip_command = true;
        let outcome = run_target(&opts).unwrap();
        assert!(outcome.clean);
        assert!(outcome.crashes.is_empty());
        assert!(outcome.new_artifacts.is_empty());
    }

    #[test]
    fn outcome_from_captured_extracts_panic() {
        let stderr = r"thread 'main' panicked at 'oops', src/lib.rs:1:1
note: run with `RUST_BACKTRACE=1`
SUMMARY: libFuzzer: deadly signal
artifact_prefix='./'; Test unit written to ./crash-aaaa
";
        let outcome = outcome_from_captured(stderr.to_string(), vec![]);
        assert!(!outcome.clean);
        assert_eq!(outcome.crashes.len(), 1);
        assert_eq!(outcome.crashes[0].summary, "oops");
    }

    #[test]
    fn run_options_constructor_sets_defaults() {
        let opts = RunOptions::new("/tmp/x", "store_mood", Duration::from_mins(1));
        assert_eq!(opts.target, "store_mood");
        assert_eq!(opts.timeout_secs, 25);
        assert_eq!(opts.rss_limit_mb, 2048);
        assert!(opts.seed.is_none());
        assert!(!opts.skip_command);
    }
}
