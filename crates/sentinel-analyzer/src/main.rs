//! `sentinel-analyzer` CLI entry point.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use sentinel_analyzer::{analyze_project, render_html, render_json, AnalyzeOptions};
use sentinel_core::{Report, Severity};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Human-readable summary (default).
    Text,
    /// Pretty-printed JSON, same shape as cartographer/fuzzer reports.
    Json,
    /// Self-contained HTML report.
    Html,
}

/// Run Tauri-aware static analysis against a project's source tree.
#[derive(Debug, Parser)]
#[command(name = "sentinel-analyzer", version, author, about)]
struct Cli {
    /// Project root to scan.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Path to write the report. Defaults to stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Optional TOML rules file extending or overriding built-in patterns.
    #[arg(long)]
    rules: Option<PathBuf>,

    /// Include test files in the scan (default skips `tests/`, `*_test.rs`, `*.test.ts`, `*.spec.ts`).
    #[arg(long)]
    include_tests: bool,

    /// Increase log verbosity. Repeat for more.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    install_tracing(cli.verbose);

    let opts = AnalyzeOptions {
        user_rules: cli.rules.clone(),
        include_tests: cli.include_tests,
    };
    let report = analyze_project(&cli.project, &opts).context("analyze project")?;

    let rendered = match cli.format {
        OutputFormat::Json => render_json(&report)?,
        OutputFormat::Html => render_html(&report),
        OutputFormat::Text => render_text(&report),
    };

    match cli.output.as_ref() {
        Some(path) => {
            std::fs::write(path, rendered.as_bytes())
                .with_context(|| format!("failed to write report to {}", path.display()))?;
            tracing::info!(output = %path.display(), "report written");
        }
        None => {
            print!("{rendered}");
            if !rendered.ends_with('\n') {
                println!();
            }
        }
    }

    if report.summary.high + report.summary.critical > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn install_tracing(verbosity: u8) {
    let filter = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env)
        .with_target(false)
        .without_time()
        .try_init();
}

fn render_text(report: &Report) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "Sentinel Analyzer v{}", report.sentinel_version);
    let _ = writeln!(s, "Project : {}", report.app_name);
    let _ = writeln!(s, "Root    : {}", report.scan_root);
    let _ = writeln!(s, "Date    : {}", report.scan_date.to_rfc3339());
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Summary : total={} critical={} high={} medium={} low={} info={}",
        report.summary.total,
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info,
    );
    let _ = writeln!(s);
    if report.findings.is_empty() {
        let _ = writeln!(s, "No findings.");
        return s;
    }
    for f in &report.findings {
        let _ = writeln!(s, "[{:>8}] {}", severity_label(f.severity), f.title);
        let _ = writeln!(s, "           id        : {}", f.id);
        let _ = writeln!(s, "           component : {}", f.component);
        if let Some(loc) = &f.location {
            let _ = match loc.line {
                Some(line) => writeln!(s, "           location  : {}:{}", loc.file, line),
                None => writeln!(s, "           location  : {}", loc.file),
            };
        }
        if !f.suggestion.is_empty() {
            let _ = writeln!(s, "           suggestion: {}", f.suggestion);
        }
        for r in &f.references {
            let _ = writeln!(s, "           ref       : {r}");
        }
        let _ = writeln!(s);
    }
    s
}

fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}
