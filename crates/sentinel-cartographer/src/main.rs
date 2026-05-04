//! `sentinel-cartographer` CLI entry point.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use sentinel_cartographer::{cartograph, AdvisoryStore, CacheStatus, CartographOptions, NvdClient};
use sentinel_core::Severity;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Human-readable summary.
    Text,
    /// Machine-readable JSON report.
    Json,
}

/// Map a Tauri / Rust project's attack surface and known CVEs.
#[derive(Debug, Parser)]
#[command(name = "sentinel-cartographer", version, author, about)]
struct Cli {
    /// Project root containing `Cargo.toml`.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Refresh the local advisory cache before scanning.
    #[arg(long)]
    refresh: bool,

    /// Skip advisory matching entirely (parser + structural findings only).
    #[arg(long, conflicts_with = "refresh")]
    no_advisories: bool,

    /// Override the cache directory (default: `$SENTINEL_HOME/advisory-db`).
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Increase log verbosity. Repeat for more.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    install_tracing(cli.verbose);

    let cache_dir = match cli.cache_dir {
        Some(p) => p,
        None => sentinel_core::io::sentinel_home()?.join("advisory-db"),
    };

    let store = if cli.no_advisories {
        None
    } else {
        let client = NvdClient::new(cache_dir.clone()).context("create advisory client")?;
        let status = client.cache_status();
        if cli.refresh || status == CacheStatus::Missing {
            tracing::info!(
                cache = %cache_dir.display(),
                status = ?status,
                "refreshing advisory cache"
            );
            if let Err(e) = client.refresh(cli.refresh).await {
                tracing::warn!(error = %e, "advisory refresh failed, continuing with whatever is cached");
            }
        }
        let loaded = match AdvisoryStore::load_from_dir(&cache_dir) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load advisory cache; continuing without");
                AdvisoryStore::new()
            }
        };
        if loaded.is_empty() {
            tracing::warn!(
                "advisory store is empty; pass --refresh once to download or --no-advisories to silence this"
            );
        }
        Some(loaded)
    };

    let report = cartograph(CartographOptions {
        root: &cli.project,
        advisories: store.as_ref(),
    })
    .context("cartograph scan failed")?;

    match cli.format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report).context("serialize report")?;
            println!("{json}");
        }
        OutputFormat::Text => print_text_report(&report),
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

fn print_text_report(report: &sentinel_core::Report) {
    println!("Sentinel Cartographer v{}", report.sentinel_version);
    println!("Project : {}", report.app_name);
    println!("Root    : {}", report.scan_root);
    println!("Date    : {}", report.scan_date.to_rfc3339());
    println!();
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

    if report.findings.is_empty() {
        println!("No findings.");
        return;
    }

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
        for r in &f.references {
            println!("           ref       : {r}");
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
