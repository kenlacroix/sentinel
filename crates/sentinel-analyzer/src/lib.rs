//! Sentinel Analyzer — Tauri-specific static analysis for source code.
//!
//! ## Scope
//!
//! The analyzer focuses on **Tauri-shaped findings** — patterns that no
//! generic tool catches well because they require knowing what
//! `#[tauri::command]` means:
//!
//! - Command-injection sinks (`#[tauri::command]` arg → `Command::new(...)`)
//! - Path-traversal sinks (`#[tauri::command]` arg → `tauri::path::resolve_path(...)`)
//! - Webview `eval()` / `new Function(string)` in IPC-handling JS/TS
//! - `dangerouslySetInnerHTML` in React/JSX webview code
//! - `unsafe` blocks inside `#[tauri::command]` functions
//! - CSP weaknesses in HTML / `tauri.conf.json` (`unsafe-eval`, `unsafe-inline`)
//! - Weak cryptographic primitives in security-sensitive context
//! - Plain HTTP URLs in `fetch()` / `Client::get(...)` calls
//!
//! Generic secret detection is out of scope. Use [gitleaks](https://github.com/gitleaks/gitleaks)
//! or [trufflehog](https://github.com/trufflesecurity/trufflehog) for that
//! work — they ship 5000+ tuned patterns and live verifier callbacks the
//! analyzer cannot replicate with regex.
//!
//! ## Architecture
//!
//! ```text
//!                          ┌──────────────┐
//!                          │   patterns   │  built-in regex library
//!                          └──────┬───────┘  + user-loaded YAML
//!                                 │
//!  ┌─────────────┐         ┌──────▼───────┐         ┌────────────┐
//!  │   scanner   │ ──────► │  matcher +   │ ──────► │  findings  │
//!  │ (walkdir)   │  files  │   dataflow   │ matches │   (Find.)  │
//!  └─────────────┘         └──────▲───────┘         └─────┬──────┘
//!                                 │                       │
//!                          ┌──────┴───────┐         ┌─────▼──────┐
//!                          │   ignores    │         │   report   │
//!                          │  comments +  │         │ JSON + HTML│
//!                          │.sentinelignore│        └────────────┘
//!                          └──────────────┘
//! ```

#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod dataflow;
pub mod findings;
pub mod ignores;
pub mod patterns;
pub mod report;
pub mod scanner;

pub use dataflow::{trace_tauri_sinks, FunctionBody, TauriCommand};
pub use findings::{matches_to_findings, Match};
pub use ignores::{parse_inline_ignores, SentinelIgnore, SuppressionMap};
pub use patterns::{builtin_patterns, load_rules_yaml, Pattern, PatternKind};
pub use report::{render_html, render_json};
pub use scanner::{analyze_project, scan_file, AnalyzeOptions};

/// Crate version string for the CLI's `--version` output.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
