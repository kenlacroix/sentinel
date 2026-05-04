//! Unified-scan orchestration: run cartographer + analyzer + (optional) fuzzer
//! and merge their findings into one [`sentinel_core::Report`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use sentinel_analyzer::AnalyzeOptions;
use sentinel_cartographer::{cartograph, AdvisoryStore, CacheStatus, CartographOptions, NvdClient};
use sentinel_core::{Finding, Report};
use sentinel_fuzzer::{
    cargo_fuzz_available, crash_to_finding, dedup_findings as dedup_fuzz, run_target, RunOptions,
};

/// Options controlling a single unified scan.
///
/// The struct has several `bool` fields by design — each one is an
/// orthogonal user-facing toggle (`--no-cartographer`, `--no-analyzer`,
/// `--no-advisories`, `--refresh-advisories`, `--include-tests`). Folding
/// them into a flag enum would obscure the 1:1 mapping with CLI flags.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ScanOptions {
    /// Project root.
    pub project: PathBuf,
    /// Skip the cartographer entirely.
    pub no_cartographer: bool,
    /// Skip the analyzer entirely.
    pub no_analyzer: bool,
    /// Optional list of fuzz target names to run.
    /// Empty means "skip the fuzzer." Each named target gets `duration` seconds.
    pub fuzz_targets: Vec<String>,
    /// Per-fuzz-target duration.
    pub fuzz_duration: Duration,
    /// Optional libFuzzer seed for reproducible fuzz runs.
    pub fuzz_seed: Option<u64>,
    /// Pass-through to the cartographer: force advisory cache refresh.
    pub refresh_advisories: bool,
    /// Pass-through to the cartographer: skip advisory matching entirely.
    pub no_advisories: bool,
    /// Pass-through to the analyzer: load extra TOML rules.
    pub analyzer_rules: Option<PathBuf>,
    /// Pass-through to the analyzer: include test files in the scan.
    pub analyzer_include_tests: bool,
}

impl ScanOptions {
    /// Construct a `ScanOptions` with sensible defaults targeting `project`.
    ///
    /// The default fuzz duration is one minute. We use `Duration::from_secs(60)`
    /// rather than `from_mins(1)` because libFuzzer's `-max_total_time` flag
    /// reads in seconds; keeping the unit consistent at the call site makes
    /// the conversion to that flag obvious.
    #[must_use]
    #[allow(clippy::duration_suboptimal_units)]
    pub fn new(project: impl Into<PathBuf>) -> Self {
        Self {
            project: project.into(),
            no_cartographer: false,
            no_analyzer: false,
            fuzz_targets: Vec::new(),
            fuzz_duration: Duration::from_secs(60),
            fuzz_seed: None,
            refresh_advisories: false,
            no_advisories: false,
            analyzer_rules: None,
            analyzer_include_tests: false,
        }
    }
}

/// Per-tool execution status, surfaced alongside the merged report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolStatus {
    /// Tool ran successfully and contributed `count` findings.
    Ran {
        /// How many findings the tool produced.
        count: usize,
    },
    /// Tool was deliberately skipped via flag.
    Skipped(&'static str),
    /// Tool failed to run; the unified scan continues with the rest.
    Failed(String),
}

/// Combined result of a unified scan: the merged report plus per-tool status.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    /// Merged findings + summary across all tools that ran.
    pub report: Report,
    /// What happened with the cartographer.
    pub cartographer: ToolStatus,
    /// What happened with the analyzer.
    pub analyzer: ToolStatus,
    /// Per-fuzz-target status.
    pub fuzz_targets: Vec<(String, ToolStatus)>,
}

/// Run a unified scan against `opts.project` and return the merged outcome.
///
/// Tool failures are surfaced via [`ToolStatus::Failed`] in the outcome
/// rather than propagated as `Err`. This matches the principle that one
/// flaky tool shouldn't black-hole the entire scan — the user wants to see
/// whatever findings the working tools produced.
///
/// # Errors
///
/// Returns an error only when the project root itself cannot be resolved
/// or every requested tool was deliberately skipped. Per-tool failures
/// land in the outcome instead.
pub async fn run_scan(opts: &ScanOptions) -> Result<ScanOutcome> {
    let root = opts
        .project
        .canonicalize()
        .with_context(|| format!("project root does not exist: {}", opts.project.display()))?;

    let mut findings: Vec<Finding> = Vec::new();
    let cartographer = run_cartographer(&root, opts, &mut findings).await;
    let analyzer = run_analyzer(&root, opts, &mut findings);
    let fuzz_targets = run_fuzz(&root, opts, &mut findings);

    let app_name = root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    let mut report = Report::new(app_name, root.to_string_lossy().into_owned(), findings);
    report.sort_findings();

    Ok(ScanOutcome {
        report,
        cartographer,
        analyzer,
        fuzz_targets,
    })
}

async fn run_cartographer(root: &Path, opts: &ScanOptions, into: &mut Vec<Finding>) -> ToolStatus {
    if opts.no_cartographer {
        return ToolStatus::Skipped("--no-cartographer");
    }

    let store = match cartographer_store(opts).await {
        Ok(s) => s,
        Err(e) => return ToolStatus::Failed(format!("advisory store: {e:#}")),
    };

    let report = match cartograph(CartographOptions {
        root,
        advisories: store.as_ref(),
    }) {
        Ok(r) => r,
        Err(e) => return ToolStatus::Failed(format!("cartograph: {e:#}")),
    };

    let count = report.findings.len();
    into.extend(report.findings);
    ToolStatus::Ran { count }
}

async fn cartographer_store(opts: &ScanOptions) -> Result<Option<AdvisoryStore>> {
    if opts.no_advisories {
        return Ok(None);
    }
    let cache_dir = sentinel_core::io::sentinel_home()?.join("advisory-db");
    let client = NvdClient::new(cache_dir.clone()).context("create advisory client")?;
    let status = client.cache_status();
    if opts.refresh_advisories || status == CacheStatus::Missing {
        if let Err(e) = client.refresh(opts.refresh_advisories).await {
            tracing::warn!(error = %e, "advisory refresh failed, using existing cache");
        }
    }
    let loaded = AdvisoryStore::load_from_dir(&cache_dir).unwrap_or_default();
    if loaded.is_empty() {
        tracing::warn!(
            "advisory store is empty; pass --refresh-advisories to populate or --no-advisories to silence"
        );
    }
    Ok(Some(loaded))
}

fn run_analyzer(root: &Path, opts: &ScanOptions, into: &mut Vec<Finding>) -> ToolStatus {
    if opts.no_analyzer {
        return ToolStatus::Skipped("--no-analyzer");
    }
    let analyzer_opts = AnalyzeOptions {
        user_rules: opts.analyzer_rules.clone(),
        include_tests: opts.analyzer_include_tests,
    };
    match sentinel_analyzer::analyze_project(root, &analyzer_opts) {
        Ok(report) => {
            let count = report.findings.len();
            into.extend(report.findings);
            ToolStatus::Ran { count }
        }
        Err(e) => ToolStatus::Failed(format!("analyzer: {e:#}")),
    }
}

fn run_fuzz(root: &Path, opts: &ScanOptions, into: &mut Vec<Finding>) -> Vec<(String, ToolStatus)> {
    if opts.fuzz_targets.is_empty() {
        return Vec::new();
    }
    if !cargo_fuzz_available() {
        return opts
            .fuzz_targets
            .iter()
            .map(|t| {
                (
                    t.clone(),
                    ToolStatus::Failed("cargo-fuzz not installed".into()),
                )
            })
            .collect();
    }

    let mut results = Vec::with_capacity(opts.fuzz_targets.len());
    for target in &opts.fuzz_targets {
        let run_opts = RunOptions {
            project_root: root.to_path_buf(),
            target: target.clone(),
            duration: opts.fuzz_duration,
            timeout_secs: 25,
            rss_limit_mb: 2048,
            seed: opts.fuzz_seed,
            skip_command: false,
        };
        match run_target(&run_opts) {
            Ok(outcome) => {
                let target_findings: Vec<Finding> = outcome
                    .crashes
                    .iter()
                    .map(|c| crash_to_finding(target, c))
                    .collect();
                let target_findings = dedup_fuzz(target_findings);
                let count = target_findings.len();
                into.extend(target_findings);
                results.push((target.clone(), ToolStatus::Ran { count }));
            }
            Err(e) => {
                results.push((target.clone(), ToolStatus::Failed(format!("{e:#}"))));
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> PathBuf {
        // Reuse the analyzer's synthetic-vuln fixture: it's a self-contained
        // tree with intentional issues across cartographer + analyzer scope.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("sentinel-analyzer")
            .join("tests")
            .join("fixtures")
            .join("synthetic_vuln")
    }

    #[tokio::test]
    async fn scan_with_both_tools_skipped_runs_no_tools() {
        let opts = ScanOptions {
            no_cartographer: true,
            no_analyzer: true,
            ..ScanOptions::new(fixture_root())
        };
        let outcome = run_scan(&opts).await.unwrap();
        assert!(matches!(outcome.cartographer, ToolStatus::Skipped(_)));
        assert!(matches!(outcome.analyzer, ToolStatus::Skipped(_)));
        assert!(outcome.fuzz_targets.is_empty());
        assert!(outcome.report.findings.is_empty());
    }

    #[tokio::test]
    async fn scan_runs_analyzer_only_when_cartographer_skipped() {
        let opts = ScanOptions {
            no_cartographer: true,
            no_analyzer: false,
            no_advisories: true,
            ..ScanOptions::new(fixture_root())
        };
        let outcome = run_scan(&opts).await.unwrap();
        assert!(matches!(outcome.cartographer, ToolStatus::Skipped(_)));
        match outcome.analyzer {
            ToolStatus::Ran { count } => assert!(
                count >= 8,
                "expected at least 8 analyzer findings, got {count}"
            ),
            other => panic!("analyzer didn't run cleanly: {other:?}"),
        }
        // Every emitted finding must come from the analyzer.
        for f in &outcome.report.findings {
            assert_eq!(
                f.tool,
                sentinel_core::Tool::Analyzer,
                "expected only analyzer findings; got {:?} from {}",
                f.tool,
                f.id
            );
        }
    }

    #[tokio::test]
    async fn scan_runs_cartographer_only_when_analyzer_skipped() {
        let opts = ScanOptions {
            no_cartographer: false,
            no_analyzer: true,
            no_advisories: true,
            ..ScanOptions::new(fixture_root())
        };
        let outcome = run_scan(&opts).await.unwrap();
        assert!(matches!(outcome.analyzer, ToolStatus::Skipped(_)));
        match outcome.cartographer {
            ToolStatus::Ran { count } => {
                assert!(count >= 1, "cartographer should produce >= 1 finding");
            }
            other => panic!("cartographer didn't run cleanly: {other:?}"),
        }
        for f in &outcome.report.findings {
            assert_eq!(f.tool, sentinel_core::Tool::Cartographer);
        }
    }

    #[tokio::test]
    async fn scan_combines_cartographer_and_analyzer_findings() {
        let opts = ScanOptions {
            no_advisories: true,
            ..ScanOptions::new(fixture_root())
        };
        let outcome = run_scan(&opts).await.unwrap();
        let cart_count = outcome
            .report
            .findings
            .iter()
            .filter(|f| f.tool == sentinel_core::Tool::Cartographer)
            .count();
        let analyzer_count = outcome
            .report
            .findings
            .iter()
            .filter(|f| f.tool == sentinel_core::Tool::Analyzer)
            .count();
        assert!(cart_count >= 1, "expected cartographer findings");
        assert!(analyzer_count >= 8, "expected analyzer findings");
        assert_eq!(
            outcome.report.summary.total,
            cart_count + analyzer_count,
            "summary total should match sum of per-tool finding counts"
        );
    }

    #[tokio::test]
    async fn fuzz_targets_without_cargo_fuzz_fail_individually() {
        // cargo-fuzz isn't installed in CI; this test documents the
        // graceful-degradation behaviour.
        let opts = ScanOptions {
            no_cartographer: true,
            no_analyzer: true,
            fuzz_targets: vec!["nonexistent".to_string()],
            ..ScanOptions::new(fixture_root())
        };
        let outcome = run_scan(&opts).await.unwrap();
        assert_eq!(outcome.fuzz_targets.len(), 1);
        match &outcome.fuzz_targets[0] {
            (name, ToolStatus::Failed(_)) => assert_eq!(name, "nonexistent"),
            other => panic!("expected failure for missing fuzz target, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn report_sorts_findings_with_critical_first() {
        let opts = ScanOptions {
            no_advisories: true,
            ..ScanOptions::new(fixture_root())
        };
        let outcome = run_scan(&opts).await.unwrap();
        let severities: Vec<_> = outcome.report.findings.iter().map(|f| f.severity).collect();
        // Verify monotonically non-increasing severity.
        for w in severities.windows(2) {
            assert!(
                w[0] >= w[1],
                "findings not sorted by severity: {severities:?}"
            );
        }
    }

    #[tokio::test]
    async fn missing_project_root_errors_loudly() {
        let opts = ScanOptions::new("/definitely/does/not/exist/sentinel-cli-test");
        let err = run_scan(&opts).await.unwrap_err();
        assert!(err.to_string().contains("project root does not exist"));
    }
}
