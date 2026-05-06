//! High-level scan orchestration: parse a project, query advisories, emit findings.

use anyhow::Result;
use sentinel_core::{Finding, Location, Report, Severity, Tool};

use crate::cve::{Advisory, AdvisoryStore};
use crate::parser::{parse_project, ParsedProject, TauriManifest};

/// Options controlling a single cartographer run.
#[derive(Debug, Clone, Copy)]
pub struct CartographOptions<'a> {
    /// Project root to scan.
    pub root: &'a std::path::Path,
    /// Optional advisory store. When `None`, only structural findings are emitted.
    pub advisories: Option<&'a AdvisoryStore>,
}

/// Run the cartographer end-to-end against `opts.root` and return a [`Report`].
///
/// # Errors
///
/// Returns an error if the project cannot be parsed (no `Cargo.toml`,
/// malformed manifests, etc.).
pub fn cartograph(opts: CartographOptions<'_>) -> Result<Report> {
    let parsed = parse_project(opts.root)?;
    let mut findings: Vec<Finding> = Vec::new();

    if let Some(store) = opts.advisories {
        findings.extend(advisory_findings(&parsed, store));
    }

    if let Some(tauri) = parsed.tauri.as_ref() {
        findings.extend(tauri_findings(tauri, &parsed));
    }

    findings.extend(surface_findings(&parsed));

    let mut report = Report::new(
        parsed.app_name.clone(),
        parsed.root.to_string_lossy().into_owned(),
        findings,
    );
    report.sort_findings();
    Ok(report)
}

fn advisory_findings(project: &ParsedProject, store: &AdvisoryStore) -> Vec<Finding> {
    // Match against resolved versions from Cargo.lock when available — that
    // is the actual version the project ships. Fall back to the
    // requirement string from Cargo.toml only when no lockfile resolution
    // exists (in which case the matcher's conservative behaviour over-reports).
    //
    // Why this matters: requirement strings like "1.0" don't parse as
    // semver, which trips the matcher's "if I can't parse it, treat as
    // potentially affected" fallback and produces decades of stale CVE
    // findings. Resolved versions like "1.0.5" parse cleanly and produce
    // precise matches.
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for dep in &project.dependencies {
        let resolved = project.resolved_versions.get(&dep.name);
        let lookup_versions: Vec<String> = match resolved {
            Some(v) if !v.is_empty() => v.clone(),
            _ => match dep.version_req.as_deref() {
                Some(req) => vec![strip_caret(req).to_string()],
                None => continue,
            },
        };

        for version in &lookup_versions {
            for adv in store.matches(&dep.name, version) {
                let key = (adv.id.clone(), dep.name.clone());
                if !seen.insert(key) {
                    continue;
                }
                out.push(advisory_to_finding(adv, dep, version, &project.app_name));
            }
        }
    }
    out
}

fn advisory_to_finding(
    adv: &Advisory,
    dep: &crate::parser::Dependency,
    matched_version: &str,
    _app: &str,
) -> Finding {
    Finding {
        id: format!("cartographer.cve.{}", adv.id),
        title: format!("{}: {}", adv.id, adv.title),
        description: build_advisory_description(adv, dep, matched_version),
        severity: severity_from_advisory(adv),
        tool: Tool::Cartographer,
        component: format!("dep:{}", dep.name),
        suggestion: build_advisory_suggestion(adv, dep),
        location: None,
        references: adv
            .references
            .iter()
            .chain(adv.aliases.iter())
            .cloned()
            .collect(),
    }
}

fn build_advisory_description(
    adv: &Advisory,
    dep: &crate::parser::Dependency,
    matched_version: &str,
) -> String {
    let mut s = format!(
        "Dependency `{}` (resolved version `{}`, requirement `{}`) is referenced by advisory {}.",
        dep.name,
        matched_version,
        dep.version_req.as_deref().unwrap_or("?"),
        adv.id,
    );
    if !adv.description.is_empty() {
        s.push_str("\n\n");
        s.push_str(&adv.description);
    }
    s
}

fn build_advisory_suggestion(adv: &Advisory, dep: &crate::parser::Dependency) -> String {
    if adv.patched_versions.is_empty() {
        format!(
            "No patched version is published; consider replacing `{}` or pinning to an unaffected version.",
            dep.name
        )
    } else {
        format!(
            "Upgrade `{}` to a patched version (one of: {}).",
            dep.name,
            adv.patched_versions.join(", ")
        )
    }
}

fn severity_from_advisory(adv: &Advisory) -> Severity {
    let raw = adv.severity.as_deref().unwrap_or("").to_ascii_lowercase();
    if raw.contains("critical") {
        Severity::Critical
    } else if raw.contains("high") {
        Severity::High
    } else if raw.contains("medium") || raw.contains("moderate") {
        Severity::Medium
    } else if raw.contains("low") {
        Severity::Low
    } else {
        // Unknown -> default to high so users notice.
        Severity::High
    }
}

fn tauri_findings(tauri: &TauriManifest, project: &ParsedProject) -> Vec<Finding> {
    let mut out = Vec::new();

    if tauri.csp_disabled {
        out.push(Finding {
            id: "cartographer.tauri.csp_disabled".to_string(),
            title: "Content-Security-Policy disabled".to_string(),
            description:
                "The Tauri configuration sets `app.security.csp` to `null`, which disables CSP \
                 enforcement for the webview. Without a CSP, any XSS or injection in your \
                 frontend immediately gains access to the IPC bridge."
                    .to_string(),
            severity: Severity::High,
            tool: Tool::Cartographer,
            component: "tauri.conf.json".to_string(),
            suggestion:
                "Set a strict CSP (e.g. `default-src 'self'; script-src 'self'`) and tighten \
                 it before shipping."
                    .to_string(),
            location: project
                .manifest_paths
                .iter()
                .find(|p| {
                    p.file_name().and_then(|s| s.to_str()) == Some("tauri.conf.json")
                        || p.file_name().and_then(|s| s.to_str()) == Some("tauri.conf.json5")
                })
                .map(|p| Location::new(p.to_string_lossy().into_owned(), None)),
            references: vec![
                "https://tauri.app/security/csp/".to_string(),
                "https://owasp.org/www-community/attacks/xss/".to_string(),
            ],
        });
    }

    if tauri.allowlist.iter().any(|s| s == "all") {
        out.push(Finding {
            id: "cartographer.tauri.allowlist_all".to_string(),
            title: "Tauri allowlist `all = true`".to_string(),
            description:
                "Every Tauri API is exposed to the webview. This eliminates the principle of \
                 least privilege and makes any frontend bug a full host compromise."
                    .to_string(),
            severity: Severity::Critical,
            tool: Tool::Cartographer,
            component: "tauri.conf.json".to_string(),
            suggestion: "Disable `tauri.allowlist.all` and enable individual APIs only as needed."
                .to_string(),
            location: None,
            references: vec!["https://tauri.app/v1/api/config/#allowlistconfig".to_string()],
        });
    }

    out
}

fn surface_findings(project: &ParsedProject) -> Vec<Finding> {
    let mut out = Vec::new();
    let total = project.dependencies.len();
    out.push(Finding {
        id: "cartographer.surface.dependency_count".to_string(),
        title: format!("{total} direct dependencies declared"),
        description: format!(
            "{total} unique direct dependencies were aggregated across {} manifest(s).",
            project.manifest_paths.len()
        ),
        severity: Severity::Info,
        tool: Tool::Cartographer,
        component: "workspace".to_string(),
        suggestion: "Audit dependencies regularly with `cargo audit` or `sentinel cartographer`."
            .to_string(),
        location: None,
        references: vec![],
    });
    out
}

fn strip_caret(req: &str) -> &str {
    let trimmed = req.trim();
    trimmed
        .strip_prefix('^')
        .or_else(|| trimmed.strip_prefix('~'))
        .or_else(|| trimmed.strip_prefix(">="))
        .or_else(|| trimmed.strip_prefix("<="))
        .or_else(|| trimmed.strip_prefix('>'))
        .or_else(|| trimmed.strip_prefix('<'))
        .or_else(|| trimmed.strip_prefix('='))
        .map_or(trimmed, str::trim_start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Dependency, DependencyKind};

    fn make_advisory(id: &str, pkg: &str, patched: &[&str], severity: &str) -> Advisory {
        Advisory {
            id: id.to_string(),
            package: pkg.to_string(),
            title: format!("{id} title"),
            description: "desc".to_string(),
            severity: Some(severity.to_string()),
            patched_versions: patched.iter().map(|s| (*s).to_string()).collect(),
            unaffected_versions: vec![],
            aliases: vec![],
            references: vec!["https://example.com".to_string()],
        }
    }

    fn make_project_with_dep(name: &str, version: &str) -> ParsedProject {
        ParsedProject {
            root: std::path::PathBuf::from("/tmp/demo"),
            app_name: "demo".to_string(),
            crate_version: Some("0.1.0".to_string()),
            dependencies: vec![Dependency {
                name: name.to_string(),
                version_req: Some(version.to_string()),
                optional: false,
                kind: DependencyKind::Normal,
            }],
            tauri: None,
            manifest_paths: vec![std::path::PathBuf::from("Cargo.toml")],
            resolved_versions: std::collections::HashMap::new(),
        }
    }

    fn make_project_with_resolved(name: &str, req: &str, resolved: &str) -> ParsedProject {
        let mut project = make_project_with_dep(name, req);
        project
            .resolved_versions
            .insert(name.to_string(), vec![resolved.to_string()]);
        project
    }

    #[test]
    fn advisory_findings_match_vulnerable_dep() {
        let project = make_project_with_dep("vuln-crate", "0.1.0");
        let mut store = AdvisoryStore::new();
        store.insert(make_advisory(
            "RUSTSEC-2024-0001",
            "vuln-crate",
            &[">=1.0.0"],
            "high",
        ));

        let findings = advisory_findings(&project, &store);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].id, "cartographer.cve.RUSTSEC-2024-0001");
    }

    #[test]
    fn advisory_findings_skip_safe_versions() {
        let project = make_project_with_dep("vuln-crate", "1.0.0");
        let mut store = AdvisoryStore::new();
        store.insert(make_advisory(
            "RUSTSEC-2024-0001",
            "vuln-crate",
            &[">=1.0.0"],
            "high",
        ));
        let findings = advisory_findings(&project, &store);
        assert!(findings.is_empty());
    }

    #[test]
    fn resolved_version_takes_precedence_over_requirement_string() {
        // Requirement "0.21" is what's in Cargo.toml. Cargo.lock resolves
        // to 0.21.7. The advisory affects only versions < 0.5.2.
        // Without lockfile resolution, "0.21" doesn't parse as semver and
        // the matcher conservatively reports a finding (false positive).
        // With lockfile resolution, "0.21.7" parses cleanly and is correctly
        // recognised as patched.
        let project = make_project_with_resolved("base64", "0.21", "0.21.7");
        let mut store = AdvisoryStore::new();
        store.insert(make_advisory(
            "RUSTSEC-2017-0004",
            "base64",
            &[">=0.5.2"],
            "high",
        ));
        let findings = advisory_findings(&project, &store);
        assert!(
            findings.is_empty(),
            "0.21.7 is past the patched 0.5.2 — no finding expected, got: {findings:?}"
        );
    }

    #[test]
    fn resolved_version_still_flags_truly_vulnerable_versions() {
        // Same shape as above, but the resolved version is genuinely vulnerable.
        let project = make_project_with_resolved("vuln-crate", "0.1", "0.1.0");
        let mut store = AdvisoryStore::new();
        store.insert(make_advisory(
            "RUSTSEC-2024-0042",
            "vuln-crate",
            &[">=1.0.0"],
            "critical",
        ));
        let findings = advisory_findings(&project, &store);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(
            findings[0].description.contains("resolved version `0.1.0`"),
            "description should expose the actual resolved version"
        );
    }

    #[test]
    fn fallback_to_requirement_string_when_no_lockfile_resolution() {
        let project = make_project_with_dep("vuln-crate", "0.1.0");
        let mut store = AdvisoryStore::new();
        store.insert(make_advisory(
            "RUSTSEC-2024-0001",
            "vuln-crate",
            &[">=1.0.0"],
            "high",
        ));
        let findings = advisory_findings(&project, &store);
        assert_eq!(
            findings.len(),
            1,
            "should still detect when only requirement string available"
        );
    }

    #[test]
    fn duplicate_advisory_across_multiple_resolved_versions_is_deduped() {
        let mut project = make_project_with_dep("vuln-crate", "*");
        project.resolved_versions.insert(
            "vuln-crate".to_string(),
            vec!["0.1.0".to_string(), "0.2.0".to_string()],
        );
        let mut store = AdvisoryStore::new();
        store.insert(make_advisory(
            "RUSTSEC-2024-0001",
            "vuln-crate",
            &[">=1.0.0"],
            "high",
        ));
        let findings = advisory_findings(&project, &store);
        assert_eq!(
            findings.len(),
            1,
            "same advisory, different resolved versions → one finding"
        );
    }

    #[test]
    fn severity_extraction_handles_descriptive_strings() {
        let cases = [
            ("CRITICAL/CVSS-9.8", Severity::Critical),
            ("high", Severity::High),
            ("Medium severity", Severity::Medium),
            ("moderate", Severity::Medium),
            ("LOW", Severity::Low),
            ("", Severity::High),
            ("no idea", Severity::High),
        ];
        for (raw, expected) in cases {
            let adv = make_advisory("X", "p", &[], raw);
            assert_eq!(severity_from_advisory(&adv), expected, "case: {raw}");
        }
    }

    #[test]
    fn strip_caret_normalizes_common_requirement_prefixes() {
        assert_eq!(strip_caret("^1.2.3"), "1.2.3");
        assert_eq!(strip_caret("~1.2"), "1.2");
        assert_eq!(strip_caret(">=1.0.0"), "1.0.0");
        assert_eq!(strip_caret("=1.0.0"), "1.0.0");
        assert_eq!(strip_caret("1.0.0"), "1.0.0");
    }

    #[test]
    fn cartograph_emits_surface_finding_even_with_no_advisories() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "").unwrap();

        let report = cartograph(CartographOptions {
            root,
            advisories: None,
        })
        .unwrap();
        assert_eq!(report.app_name, "x");
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "cartographer.surface.dependency_count"));
    }

    #[test]
    fn cartograph_flags_disabled_csp() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "").unwrap();
        std::fs::write(
            root.join("tauri.conf.json"),
            r#"{
                "productName": "X",
                "version": "0.1.0",
                "app": { "security": { "csp": null } }
            }"#,
        )
        .unwrap();

        let report = cartograph(CartographOptions {
            root,
            advisories: None,
        })
        .unwrap();
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "cartographer.tauri.csp_disabled"));
    }
}
