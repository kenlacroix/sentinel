//! `sentinel-fuzzer` CLI entry point.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sentinel_core::{Finding, Report, Severity, Tool};
use sentinel_fuzzer::{
    cargo_fuzz_available, crash_to_finding, dedup_findings, discover_targets, run_target,
    RunOptions,
};
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Human-readable summary.
    Text,
    /// Machine-readable JSON report.
    Json,
}

/// Drive cargo-fuzz against a Tauri project and emit a Sentinel report.
#[derive(Debug, Parser)]
#[command(name = "sentinel-fuzzer", version, author, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run a single fuzz target for the requested duration.
    Run(RunCmd),
    /// List discovered fuzz targets in the project.
    ListTargets(ListTargetsCmd),
    /// Check that the toolchain (cargo-fuzz, nightly) is set up.
    Doctor,
}

#[derive(Debug, Parser)]
struct RunCmd {
    /// Project root containing `fuzz/`.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Fuzz target name (the filename stem under `fuzz/fuzz_targets/`).
    #[arg(long)]
    target: String,

    /// Duration in seconds.
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Optional seed for reproducible runs.
    #[arg(long)]
    seed: Option<u64>,

    /// Per-input timeout in seconds.
    #[arg(long, default_value_t = 25)]
    timeout: u32,

    /// Per-process RSS limit in MB.
    #[arg(long, default_value_t = 2048)]
    rss_limit_mb: u32,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Increase log verbosity. Repeat for more.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Debug, Parser)]
struct ListTargetsCmd {
    /// Project root containing `fuzz/`.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Run(cmd) => run(&cmd),
        Cmd::ListTargets(cmd) => list_targets(&cmd),
        Cmd::Doctor => doctor(),
    }
}

fn run(cmd: &RunCmd) -> Result<()> {
    install_tracing(cmd.verbose);

    let targets = discover_targets(&cmd.project).context("discover fuzz targets")?;
    if !targets.iter().any(|t| t.name == cmd.target) {
        let names: Vec<&str> = targets.iter().map(|t| t.name.as_str()).collect();
        anyhow::bail!(
            "fuzz target `{}` not found under {}/fuzz/fuzz_targets/. \
             Available targets: {}",
            cmd.target,
            cmd.project.display(),
            if names.is_empty() {
                "(none)".to_string()
            } else {
                names.join(", ")
            }
        );
    }

    if !cargo_fuzz_available() {
        anyhow::bail!(
            "cargo-fuzz is not installed.\n  Install:  cargo install cargo-fuzz\n  Toolchain: rustup toolchain install nightly\n\nRe-run with `sentinel-fuzzer doctor` once installed."
        );
    }

    let opts = RunOptions {
        project_root: cmd.project.clone(),
        target: cmd.target.clone(),
        duration: Duration::from_secs(cmd.duration),
        timeout_secs: cmd.timeout,
        rss_limit_mb: cmd.rss_limit_mb,
        seed: cmd.seed,
        skip_command: false,
    };

    tracing::info!(
        target = %cmd.target,
        duration_secs = cmd.duration,
        "starting fuzz run"
    );
    let outcome = run_target(&opts).context("run target")?;

    let findings: Vec<Finding> = outcome
        .crashes
        .iter()
        .map(|c| crash_to_finding(&cmd.target, c))
        .collect();
    let findings = dedup_findings(findings);

    let app_name = cmd
        .project
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().and_then(|s| s.to_str()).map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());

    let mut report = Report::new(
        app_name,
        cmd.project.to_string_lossy().into_owned(),
        findings,
    );
    report.sort_findings();

    match cmd.format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report).context("serialize report")?;
            println!("{json}");
        }
        OutputFormat::Text => print_text_report(&cmd.target, &report, outcome.clean),
    }

    // Exit non-zero if we found crashes, so CI integrations can gate on it.
    if report.summary.high + report.summary.critical > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn list_targets(cmd: &ListTargetsCmd) -> Result<()> {
    let targets = discover_targets(&cmd.project).context("discover fuzz targets")?;
    if targets.is_empty() {
        eprintln!(
            "no fuzz targets found under {}/fuzz/fuzz_targets/",
            cmd.project.display()
        );
        return Ok(());
    }
    for t in &targets {
        println!("{}\t{}", t.name, t.source_path.display());
    }
    Ok(())
}

fn doctor() -> Result<()> {
    let cargo_fuzz = cargo_fuzz_available();
    let nightly = nightly_available();
    println!("cargo-fuzz available : {}", yes_no(cargo_fuzz));
    println!("nightly toolchain    : {}", yes_no(nightly));
    if !cargo_fuzz {
        println!();
        println!("To install cargo-fuzz:  cargo install cargo-fuzz");
    }
    if !nightly {
        println!();
        println!("To install nightly:     rustup toolchain install nightly");
    }
    if cargo_fuzz && nightly {
        println!();
        println!("Toolchain looks good. Try `sentinel-fuzzer list-targets <project>`.");
    } else {
        std::process::exit(2);
    }
    Ok(())
}

fn nightly_available() -> bool {
    std::process::Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("nightly"))
        .unwrap_or(false)
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
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

fn print_text_report(target: &str, report: &Report, clean: bool) {
    println!("Sentinel Fuzzer v{}", report.sentinel_version);
    println!("Project : {}", report.app_name);
    println!("Root    : {}", report.scan_root);
    println!("Target  : {target}");
    println!("Date    : {}", report.scan_date.to_rfc3339());
    println!();
    if clean {
        println!("Clean run — no crashes detected.");
        return;
    }
    println!(
        "Summary : total={} critical={} high={} medium={} low={} info={}",
        report.summary.total,
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info,
    );
    println!();
    for f in &report.findings {
        println!("[{:>8}] {}", severity_label(f.severity), f.title);
        println!("           id        : {}", f.id);
        println!("           component : {}", f.component);
        if let Some(loc) = &f.location {
            match loc.line {
                Some(line) => println!("           location  : {}:{}", loc.file, line),
                None => println!("           location  : {}", loc.file),
            }
        }
        if !f.suggestion.is_empty() {
            println!("           suggestion: {}", f.suggestion);
        }
        if matches!(f.tool, Tool::Fuzzer) && !f.description.is_empty() {
            // Indent the long description nicely.
            for line in f.description.lines() {
                println!("           desc      : {line}");
            }
        }
        println!();
    }
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}
