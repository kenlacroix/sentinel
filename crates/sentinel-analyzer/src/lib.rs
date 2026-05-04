//! Sentinel Analyzer — pattern-based static analysis for Tauri source code.
//!
//! This crate is a stub. The full implementation lands in Week 4 of the MVP
//! plan: pattern library, file walker, simple dataflow tracer, HTML report.

#![deny(missing_docs)]
#![warn(clippy::all)]

/// Placeholder so the crate has a stable public API surface.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
