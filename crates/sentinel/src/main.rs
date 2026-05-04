//! `sentinel` — unified CLI entry point.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sentinel_analyzer::{render_html as analyzer_html, render_json as analyzer_json};
use sentinel_cli::{
    doctor::{all_ok, run_all_checks},
    run_scan, ScanOptions, ScanOutcome,
};
use sentinel_core::{Severity, Tool};
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Human-readable text summary (default).
    Text,
    /// Pretty-printed JSON, same shape as individual tool reports.
    Json,
    /// Self-contained HTML report.
    Html,
}

/// Sentinel — security auditor for Tauri applications.
///
/// `sentinel scan` runs the cartographer, analyzer, and (optionally) the
/// fuzzer in one pass and emits a merged report tagged per-finding by tool.
#[derive(Debug, Parser)]
#[command(name = "sentinel", version, author, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run a unified security scan against a project.
    Scan(ScanArgs),
    /// Diagnose toolchain readiness across all sub-tools.
    Doctor,
}

#[derive(Debug, Parser)]
struct ScanArgs {
    /// Project root to scan.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Write the rendered report to this path instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Skip the cartographer (dependency CVE + Tauri config audit).
    #[arg(long)]
    no_cartographer: bool,

    /// Skip the analyzer (Tauri-aware static analysis).
    #[arg(long)]
    no_analyzer: bool,

    /// Skip advisory matching in the cartographer (faster, no network).
    #[arg(long)]
    no_advisories: bool,

    /// Force the cartographer to refresh its advisory cache.
    #[arg(long, conflicts_with = "no_advisories")]
    refresh_advisories: bool,

    /// Run this fuzz target (can be repeated). Requires `cargo-fuzz` + nightly.
    #[arg(long = "fuzz", value_name = "TARGET")]
    fuzz_targets: Vec<String>,

    /// Per-fuzz-target duration, in seconds.
    #[arg(long, default_value_t = 60)]
    fuzz_duration: u64,

    /// libFuzzer seed for reproducible fuzz runs (per-target).
    #[arg(long)]
    fuzz_seed: Option<u64>,

    /// Path to a TOML file with extra analyzer rules.
    #[arg(long)]
    rules: Option<PathBuf>,

    /// Include test files in the analyzer scan (default: skip).
    #[arg(long)]
    include_tests: bool,

    /// Increase log verbosity. Repeat for more.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Scan(args) => run_scan_cmd(args).await,
        Cmd::Doctor => run_doctor_cmd(),
    }
}

async fn run_scan_cmd(args: ScanArgs) -> Result<()> {
    install_tracing(args.verbose);

    let opts = ScanOptions {
        project: args.project.clone(),
        no_cartographer: args.no_cartographer,
        no_analyzer: args.no_analyzer,
        no_advisories: args.no_advisories,
        refresh_advisories: args.refresh_advisories,
        fuzz_targets: args.fuzz_targets,
        fuzz_duration: Duration::from_secs(args.fuzz_duration),
        fuzz_seed: args.fuzz_seed,
        analyzer_rules: args.rules,
        analyzer_include_tests: args.include_tests,
    };

    let outcome = run_scan(&opts).await.context("unified scan failed")?;
    let rendered = match args.format {
        OutputFormat::Json => analyzer_json(&outcome.report)?,
        OutputFormat::Html => analyzer_html(&outcome.report),
        OutputFormat::Text => render_text(&outcome),
    };

    match args.output.as_ref() {
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

    if outcome.report.summary.high + outcome.report.summary.critical > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn run_doctor_cmd() -> Result<()> {
    let checks = run_all_checks();
    let max_label = checks.iter().map(|c| c.label.len()).max().unwrap_or(0);
    println!("Sentinel doctor — toolchain status");
    println!();
    for c in &checks {
        let mark = if c.ok { "✓" } else { "✗" };
        println!(
            "  {mark} {label:<width$}  ({required})",
            mark = mark,
            label = c.label,
            width = max_label,
            required = c.required_for,
        );
    }
    println!();
    let missing: Vec<_> = checks.iter().filter(|c| !c.ok).collect();
    if missing.is_empty() {
        println!("All checks passed. Try `sentinel scan <project>`.");
        Ok(())
    } else {
        println!("Some dependencies are missing:");
        for c in &missing {
            println!("  • {label}: {hint}", label = c.label, hint = c.fix_hint);
        }
        if !all_ok(&checks) {
            std::process::exit(2);
        }
        Ok(())
    }
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

fn render_text(outcome: &ScanOutcome) -> String {
    use std::fmt::Write;
    let report = &outcome.report;
    let mut s = String::new();
    let _ = writeln!(s, "Sentinel v{}", report.sentinel_version);
    let _ = writeln!(s, "Project : {}", report.app_name);
    let _ = writeln!(s, "Root    : {}", report.scan_root);
    let _ = writeln!(s, "Date    : {}", report.scan_date.to_rfc3339());
    let _ = writeln!(s);
    let _ = writeln!(s, "Tools:");
    let _ = writeln!(
        s,
        "  cartographer : {}",
        tool_status_line(&outcome.cartographer)
    );
    let _ = writeln!(
        s,
        "  analyzer     : {}",
        tool_status_line(&outcome.analyzer)
    );
    if outcome.fuzz_targets.is_empty() {
        let _ = writeln!(s, "  fuzzer       : not requested");
    } else {
        for (target, status) in &outcome.fuzz_targets {
            let _ = writeln!(s, "  fuzz:{target:<8} : {}", tool_status_line(status));
        }
    }
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
        let _ = writeln!(
            s,
            "[{:>8}] [{:<13}] {}",
            severity_label(f.severity),
            tool_label(f.tool),
            f.title
        );
        let _ = writeln!(s, "             id        : {}", f.id);
        let _ = writeln!(s, "             component : {}", f.component);
        if let Some(loc) = &f.location {
            let _ = match loc.line {
                Some(line) => writeln!(s, "             location  : {}:{}", loc.file, line),
                None => writeln!(s, "             location  : {}", loc.file),
            };
        }
        if !f.suggestion.is_empty() {
            let _ = writeln!(s, "             suggestion: {}", f.suggestion);
        }
        for r in &f.references {
            let _ = writeln!(s, "             ref       : {r}");
        }
        let _ = writeln!(s);
    }
    s
}

fn tool_status_line(status: &sentinel_cli::scan::ToolStatus) -> String {
    use sentinel_cli::scan::ToolStatus;
    match status {
        ToolStatus::Ran { count } => format!("ran ({count} findings)"),
        ToolStatus::Skipped(reason) => format!("skipped ({reason})"),
        ToolStatus::Failed(err) => format!("failed: {err}"),
    }
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

fn tool_label(tool: Tool) -> &'static str {
    match tool {
        Tool::Cartographer => "cartographer",
        Tool::Fuzzer => "fuzzer",
        Tool::Analyzer => "analyzer",
    }
}
