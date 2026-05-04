//! Sentinel Cartographer — attack-surface and dependency mapping for Tauri projects.
//!
//! The cartographer parses the project's `Cargo.toml` and `tauri.conf.json`,
//! then cross-references each dependency against an offline-first CVE feed.
//! Findings are emitted as [`sentinel_core::Finding`]s suitable for inclusion
//! in a unified scan report.

#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod cve;
pub mod parser;
pub mod scan;

pub use cve::{Advisory, AdvisoryStore, CacheStatus, NvdClient};
pub use parser::{Dependency, ParsedProject, TauriManifest};
pub use scan::{cartograph, CartographOptions};
