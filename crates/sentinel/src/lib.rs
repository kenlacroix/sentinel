//! Unified Sentinel CLI library.
//!
//! Composes the three Sentinel sub-tools — cartographer, analyzer, fuzzer —
//! into a single `scan` operation that emits one merged
//! [`sentinel_core::Report`] tagged per-finding by which tool produced it.
//!
//! ## Why a separate crate
//!
//! Each tool's library is independently usable, but the combined-scan logic
//! plus the shared `doctor` command live above any individual tool.
//! Putting them in their own crate keeps the dependency graph one-way:
//! `sentinel` depends on the three sub-crates; the sub-crates do not depend
//! on each other.

#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod doctor;
pub mod scan;

pub use scan::{run_scan, ScanOptions, ScanOutcome};

/// Crate version exposed for the CLI's `--version` output.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
