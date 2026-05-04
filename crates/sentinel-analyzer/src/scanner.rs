//! File-walking scanner that ties the [`crate::patterns`] +
//! [`crate::dataflow`] + [`crate::ignores`] + [`crate::findings`] modules
//! together into the top-level analyze loop.

use anyhow::{Context, Result};
use sentinel_core::{scan as core_scan, Finding, Report};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::dataflow::{
    default_sink_patterns, extract_tauri_commands, is_in_line_comment, trace_tauri_sinks,
    trace_unsafe_in_commands,
};
use crate::findings::{dedup_findings, matches_to_findings, Match};
use crate::ignores::{parse_inline_ignores, SentinelIgnore};
use crate::patterns::{builtin_patterns, load_rules_yaml, merge_patterns, Pattern, PatternKind};

/// Hard cap on file size — anything larger is almost certainly a generated
/// bundle, lockfile, or vendored artefact. Skipping these keeps the analyzer
/// fast and signal-rich.
const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

/// Maximum traversal depth, mirrors the cartographer's choice. Defends
/// against pathological symlink loops that escape the ignore list.
const MAX_SCAN_DEPTH: usize = 10;

/// Options controlling a project-level analyzer run.
#[derive(Debug, Clone, Default)]
pub struct AnalyzeOptions {
    /// Optional path to a user TOML rules file. `None` ⇒ built-ins only.
    pub user_rules: Option<PathBuf>,
    /// Include test files (`tests/**`, `*_test.rs`, `*.test.ts`, ...).
    /// Defaults to false because patterns intentionally placed in test
    /// fixtures (e.g. `eval` to verify a sandbox) shouldn't fire.
    pub include_tests: bool,
}

/// Walk `project_root`, scan every applicable source file, run dataflow
/// against every Rust file with `#[tauri::command]` annotations, dedup,
/// and return a [`Report`].
///
/// # Errors
///
/// Returns an error if the project root cannot be canonicalized or the user
/// rules file is malformed. Per-file IO errors are logged and skipped.
pub fn analyze_project(project_root: &Path, opts: &AnalyzeOptions) -> Result<Report> {
    let root = project_root
        .canonicalize()
        .with_context(|| format!("project root does not exist: {}", project_root.display()))?;

    let mut patterns = builtin_patterns();
    if let Some(path) = opts.user_rules.as_ref() {
        let user = load_rules_yaml(path)?;
        patterns = merge_patterns(patterns, user);
    }
    let sinks = default_sink_patterns()?;
    let ignore = SentinelIgnore::load(&root);

    let allowed_exts = collect_extensions(&patterns);
    let mut findings: Vec<Finding> = Vec::new();
    let mut files_scanned = 0_usize;

    for entry in WalkDir::new(&root)
        .max_depth(MAX_SCAN_DEPTH)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !core_scan::is_ignored_path(e.path()))
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let Some(ext) = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
        else {
            continue;
        };
        if !allowed_exts.contains(ext.as_str()) {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .map_or_else(|_| path.to_path_buf(), Path::to_path_buf);
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        if ignore.is_ignored(&rel_str) {
            continue;
        }
        if !opts.include_tests && looks_like_test(&rel_str) {
            continue;
        }
        if entry.metadata().is_ok_and(|m| m.len() > MAX_FILE_SIZE) {
            tracing::debug!(path = %rel_str, "skipping file larger than 5MB");
            continue;
        }

        match scan_file(path, &rel_str, &ext, &patterns, &sinks) {
            Ok(file_findings) => {
                findings.extend(file_findings);
                files_scanned += 1;
            }
            Err(e) => {
                tracing::warn!(path = %rel_str, error = %e, "skipping unreadable file");
            }
        }
    }

    let app_name = root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    let mut report = Report::new(
        app_name,
        root.to_string_lossy().into_owned(),
        dedup_findings(findings),
    );
    report.sort_findings();
    tracing::info!(
        files = files_scanned,
        findings = report.summary.total,
        "analyzer complete"
    );
    Ok(report)
}

/// Run all matchers against a single file's content. Public for tests.
///
/// `relative_path` is what shows up in the `Finding.location.file` — pass
/// the path relative to the project root.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn scan_file(
    path: &Path,
    relative_path: &str,
    ext_lc: &str,
    patterns: &[Pattern],
    sinks: &[crate::dataflow::SinkPattern],
) -> Result<Vec<Finding>> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(scan_source(&source, relative_path, ext_lc, patterns, sinks))
}

/// Pure variant of [`scan_file`] driven by an in-memory source string.
/// Useful for tests and the synthetic-vuln fixture.
#[must_use]
pub fn scan_source(
    source: &str,
    relative_path: &str,
    ext_lc: &str,
    patterns: &[Pattern],
    sinks: &[crate::dataflow::SinkPattern],
) -> Vec<Finding> {
    let suppressions = parse_inline_ignores(source);
    let mut matches: Vec<Match> = Vec::new();

    // Regex matchers that apply to this extension.
    for pattern in patterns
        .iter()
        .filter(|p| p.kind == PatternKind::Regex && p.applies_to_extension(ext_lc))
    {
        let Ok(re) = pattern.compiled() else { continue };
        for m in re.find_iter(source) {
            if is_in_line_comment(source, m.start()) {
                continue;
            }
            let line = line_at(source, m.start());
            if suppressions.is_suppressed(line, &pattern.id) {
                continue;
            }
            matches.push(Match {
                rule_id: pattern.id.clone(),
                line,
                column: 1,
                snippet: clip(m.as_str(), 200),
            });
        }
    }

    // Dataflow matchers (Rust files only — no other ext exposes #[tauri::command]).
    if ext_lc == "rs" {
        let cmds = extract_tauri_commands(source);
        if !cmds.is_empty() {
            let sink_matches = trace_tauri_sinks(source, &cmds, sinks);
            for m in sink_matches {
                if !suppressions.is_suppressed(m.line, &m.rule_id) {
                    matches.push(m);
                }
            }
            for m in trace_unsafe_in_commands(source, &cmds) {
                if !suppressions.is_suppressed(m.line, &m.rule_id) {
                    matches.push(m);
                }
            }
        }
    }

    matches_to_findings(&matches, relative_path, patterns)
}

fn collect_extensions(patterns: &[Pattern]) -> HashSet<&str> {
    let mut exts: HashSet<&str> = patterns
        .iter()
        .flat_map(|p| p.extensions.iter().map(String::as_str))
        .collect();
    // Always allow .rs so dataflow can run even if the only Rust pattern is
    // dataflow-typed (which has no `extensions` consulted by the regex path).
    exts.insert("rs");
    exts
}

fn looks_like_test(rel_path: &str) -> bool {
    if rel_path.contains("/tests/") || rel_path.starts_with("tests/") {
        return true;
    }
    if let Some(stem) = std::path::Path::new(rel_path)
        .file_stem()
        .and_then(|s| s.to_str())
    {
        if stem.starts_with("test_") || stem.ends_with("_test") {
            return true;
        }
    }
    let name = std::path::Path::new(rel_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if name.ends_with(".test.ts")
        || name.ends_with(".test.tsx")
        || name.ends_with(".test.js")
        || name.ends_with(".spec.ts")
        || name.ends_with(".spec.tsx")
        || name.ends_with(".spec.js")
    {
        return true;
    }
    false
}

fn line_at(source: &str, off: usize) -> u32 {
    let safe = off.min(source.len());
    let n = source[..safe].matches('\n').count() + 1;
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max - 1).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::builtin_patterns;

    #[test]
    fn looks_like_test_recognises_common_layouts() {
        for path in [
            "tests/api.rs",
            "src/tests/foo.rs",
            "src/integration/tests/x.rs",
            "src/foo_test.rs",
            "src/test_foo.rs",
            "src/Foo.test.tsx",
            "src/Foo.spec.ts",
        ] {
            assert!(looks_like_test(path), "{path} should be a test path");
        }
    }

    #[test]
    fn looks_like_test_does_not_match_normal_files() {
        for path in ["src/main.rs", "src/lib.rs", "src/App.tsx", "src/api.ts"] {
            assert!(!looks_like_test(path), "{path} should NOT be a test path");
        }
    }

    #[test]
    fn scan_source_emits_high_finding_for_eval() {
        let patterns = builtin_patterns();
        let sinks = default_sink_patterns().unwrap();
        let src = "// frontend module\nconst result = eval(userInput);\n";
        let findings = scan_source(src, "src/App.tsx", "tsx", &patterns, &sinks);
        assert!(findings.iter().any(|f| f.id.contains("webview.eval")));
        assert!(findings
            .iter()
            .any(|f| f.severity == sentinel_core::Severity::High));
    }

    #[test]
    fn scan_source_respects_inline_ignore() {
        let patterns = builtin_patterns();
        let sinks = default_sink_patterns().unwrap();
        let src = "const result = eval(x); // sentinel:ignore-rule:webview.eval\n";
        let findings = scan_source(src, "src/App.tsx", "tsx", &patterns, &sinks);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_source_runs_dataflow_on_rust() {
        let patterns = builtin_patterns();
        let sinks = default_sink_patterns().unwrap();
        let src =
            "#[tauri::command]\nfn run(input: String) {\n    Command::new(&input).spawn();\n}\n";
        let findings = scan_source(src, "src-tauri/src/main.rs", "rs", &patterns, &sinks);
        assert!(findings
            .iter()
            .any(|f| f.id.contains("tauri.command_injection")));
    }

    #[test]
    fn analyze_project_finds_seeded_eval_in_tsx() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src").join("App.tsx"),
            "export default function App() { return eval('1'); }\n",
        )
        .unwrap();
        let report = analyze_project(root, &AnalyzeOptions::default()).unwrap();
        assert!(report
            .findings
            .iter()
            .any(|f| f.id.contains("webview.eval")));
    }

    #[test]
    fn analyze_project_skips_target_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("target")).unwrap();
        // Plant a finding inside target/ that should be ignored by core_scan::is_ignored_path
        std::fs::write(root.join("target").join("hot.tsx"), "eval(x);\n").unwrap();
        // And a real source file at top level
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src").join("App.tsx"), "// no findings\n").unwrap();
        let report = analyze_project(root, &AnalyzeOptions::default()).unwrap();
        assert!(report.findings.is_empty(), "target/ should be skipped");
    }

    #[test]
    fn analyze_project_skips_test_files_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src").join("App.test.tsx"), "eval(x);\n").unwrap();
        let report = analyze_project(root, &AnalyzeOptions::default()).unwrap();
        assert!(report.findings.is_empty(), "test files should be excluded");
    }

    #[test]
    fn analyze_project_includes_test_files_with_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src").join("App.test.tsx"), "eval(x);\n").unwrap();
        let opts = AnalyzeOptions {
            include_tests: true,
            ..AnalyzeOptions::default()
        };
        let report = analyze_project(root, &opts).unwrap();
        assert!(report
            .findings
            .iter()
            .any(|f| f.id.contains("webview.eval")));
    }

    #[test]
    fn analyze_project_respects_sentinelignore() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src").join("App.tsx"), "eval(x);\n").unwrap();
        std::fs::write(root.join(".sentinelignore"), "src/App.tsx\n").unwrap();
        let report = analyze_project(root, &AnalyzeOptions::default()).unwrap();
        assert!(report.findings.is_empty());
    }
}
