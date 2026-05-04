//! Sentinel Fuzzer — thin wrapper over `cargo-fuzz` for Tauri command handlers.
//!
//! ## Architecture
//!
//! Sentinel does **not** implement its own mutation engine, crash detector,
//! or minimizer. Those belong to libFuzzer (via `cargo-fuzz`), which gets
//! coverage-guided mutation, sanitizer integration, and corpus persistence
//! for free. Sentinel's job is the layer above:
//!
//! 1. **Discovery** — find user-authored fuzz targets in `<project>/fuzz/fuzz_targets/`.
//! 2. **Runner** — invoke `cargo +nightly fuzz run <target>` with the requested duration.
//! 3. **Parse** — turn libFuzzer's stderr into structured [`CrashInfo`].
//! 4. **Findings** — convert crashes to [`sentinel_core::Finding`]s, dedup by
//!    panic location and top stack frame, infer severity.
//!
//! Users opt in by writing fuzz targets in their project following the
//! template at `templates/fuzz_target.rs.tera` — typically a few lines that
//! invoke `tauri::test::mock_builder()` with an [`arbitrary`-derived](https://docs.rs/arbitrary)
//! input type.
//!
//! ## What this crate intentionally does not do
//!
//! - No bitflip / havoc / dictionary mutation — libFuzzer does this better.
//! - No `std::panic::catch_unwind` harness — libFuzzer's signal handler is
//!   strictly more capable (catches panics, ASAN reports, OOM, timeouts).
//! - No corpus management — `<project>/fuzz/corpus/<target>/` is canonical.
//! - No `#[tauri::command]` source-introspection — the user writes one fuzz
//!   target file per command they want fuzzed (convention beats codegen for MVP).

#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod discovery;
pub mod findings;
pub mod parse;
pub mod runner;

pub use discovery::{discover_targets, FuzzTarget};
pub use findings::{crash_to_finding, dedup_findings};
pub use parse::{parse_libfuzzer_stderr, CrashInfo, CrashKind};
pub use runner::{cargo_fuzz_available, outcome_from_captured, run_target, RunOptions, RunOutcome};

/// Crate version exposed for the CLI's `--version` output.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
