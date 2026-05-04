//! Parsers for `Cargo.toml` and `tauri.conf.json`.
//!
//! These are intentionally tolerant — a Tauri project may live anywhere in a
//! workspace, and `tauri.conf.json` schemas have shifted between Tauri v1 and
//! v2. We extract the fields the cartographer needs and ignore the rest.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Maximum depth we traverse looking for Cargo or Tauri manifests.
///
/// Deep `node_modules` and `target` directories never contain the project
/// manifest, and we avoid them explicitly below — but a hard cap protects us
/// against pathological symlink loops.
const MAX_SCAN_DEPTH: usize = 6;

/// A single direct dependency declared in `Cargo.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dependency {
    /// Crate name as published on crates.io (or the local alias).
    pub name: String,
    /// Version requirement string as written in the manifest, e.g. `"^1.0"`.
    ///
    /// `None` for path-only or git dependencies that omit a version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_req: Option<String>,
    /// Whether the dependency was declared optional.
    pub optional: bool,
    /// Which manifest section the dep came from.
    pub kind: DependencyKind,
}

/// Section of `Cargo.toml` a dependency was declared in.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyKind {
    /// `[dependencies]`
    Normal,
    /// `[dev-dependencies]`
    Dev,
    /// `[build-dependencies]`
    Build,
}

/// A subset of `tauri.conf.json` fields relevant to the cartographer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TauriManifest {
    /// `productName`, `package.productName`, or fallback to crate name.
    pub product_name: Option<String>,
    /// `version` from `tauri.conf.json`, when set.
    pub version: Option<String>,
    /// Plugin / feature names enabled in `app.security.csp`, `tauri.bundle`,
    /// `tauri.allowlist`, or `app.security.capabilities`.
    pub features: Vec<String>,
    /// Whether the manifest opts into a permissive CSP.
    pub csp_disabled: bool,
    /// Allowlist of Tauri APIs (v1) — empty for v2 projects.
    pub allowlist: Vec<String>,
}

/// Result of parsing a project: dependencies plus optional Tauri manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedProject {
    /// Project root directory (absolute).
    pub root: PathBuf,
    /// Project / app name.
    pub app_name: String,
    /// Crate version as declared in `Cargo.toml`.
    pub crate_version: Option<String>,
    /// All direct dependencies aggregated from every `Cargo.toml` we found.
    pub dependencies: Vec<Dependency>,
    /// Tauri configuration when one is present.
    pub tauri: Option<TauriManifest>,
    /// Manifest paths we read, relative to `root`.
    pub manifest_paths: Vec<PathBuf>,
}

/// Walk `root`, parsing every `Cargo.toml` and `tauri.conf.json` we find.
///
/// Skips `target/`, `node_modules/`, `.git/`, and other heavyweight
/// directories that never contain a project manifest.
///
/// # Errors
///
/// Returns an error if no `Cargo.toml` is found, or if a manifest is present
/// but malformed.
pub fn parse_project(root: &Path) -> Result<ParsedProject> {
    let root = root
        .canonicalize()
        .with_context(|| format!("project root does not exist: {}", root.display()))?;

    let mut deps: Vec<Dependency> = Vec::new();
    let mut manifest_paths: Vec<PathBuf> = Vec::new();
    let mut app_name: Option<String> = None;
    let mut crate_version: Option<String> = None;
    let mut tauri: Option<TauriManifest> = None;

    for entry in WalkDir::new(&root)
        .max_depth(MAX_SCAN_DEPTH)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.path()))
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };

        match file_name {
            "Cargo.toml" => {
                let raw = std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                let parsed = parse_cargo_toml(&raw)
                    .with_context(|| format!("invalid Cargo.toml at {}", path.display()))?;
                if app_name.is_none() {
                    app_name = parsed.crate_name;
                }
                if crate_version.is_none() {
                    crate_version = parsed.crate_version;
                }
                deps.extend(parsed.dependencies);
                manifest_paths.push(relativize(&root, path));
            }
            "tauri.conf.json" | "tauri.conf.json5" => {
                let raw = std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                let manifest = parse_tauri_conf(&raw)
                    .with_context(|| format!("invalid {file_name} at {}", path.display()))?;
                manifest_paths.push(relativize(&root, path));
                tauri = Some(manifest);
            }
            _ => {}
        }
    }

    if manifest_paths.iter().all(|p| !p.ends_with("Cargo.toml")) {
        anyhow::bail!(
            "no Cargo.toml found under {} (depth <= {})",
            root.display(),
            MAX_SCAN_DEPTH,
        );
    }

    deps.sort_by(|a, b| a.name.cmp(&b.name).then(a.kind.cmp_kind(b.kind)));
    deps.dedup_by(|a, b| a.name == b.name && a.version_req == b.version_req && a.kind == b.kind);

    Ok(ParsedProject {
        root: root.clone(),
        app_name: app_name.unwrap_or_else(|| root_name(&root)),
        crate_version,
        dependencies: deps,
        tauri,
        manifest_paths,
    })
}

/// Parsed representation of a single `Cargo.toml` file.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CargoTomlFile {
    /// Crate name (`[package].name`), if any.
    pub crate_name: Option<String>,
    /// Crate version (`[package].version`), if any.
    pub crate_version: Option<String>,
    /// Direct dependencies declared in this file.
    pub dependencies: Vec<Dependency>,
}

/// Parse a single `Cargo.toml` string into a [`CargoTomlFile`].
///
/// # Errors
///
/// Returns an error if the input is not valid TOML.
pub fn parse_cargo_toml(raw: &str) -> Result<CargoTomlFile> {
    use toml::Value;

    let value: Value = toml::from_str(raw).context("not valid TOML")?;

    let mut out = CargoTomlFile::default();

    if let Some(pkg) = value.get("package").and_then(Value::as_table) {
        out.crate_name = pkg.get("name").and_then(Value::as_str).map(str::to_string);
        out.crate_version = pkg
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_string);
    }

    extract_deps(
        &value,
        "dependencies",
        DependencyKind::Normal,
        &mut out.dependencies,
    );
    extract_deps(
        &value,
        "dev-dependencies",
        DependencyKind::Dev,
        &mut out.dependencies,
    );
    extract_deps(
        &value,
        "build-dependencies",
        DependencyKind::Build,
        &mut out.dependencies,
    );

    // `[target.'cfg(...)'.dependencies]` blocks: descend one level.
    if let Some(targets) = value.get("target").and_then(Value::as_table) {
        for cfg_table in targets.values() {
            extract_deps(
                cfg_table,
                "dependencies",
                DependencyKind::Normal,
                &mut out.dependencies,
            );
            extract_deps(
                cfg_table,
                "dev-dependencies",
                DependencyKind::Dev,
                &mut out.dependencies,
            );
            extract_deps(
                cfg_table,
                "build-dependencies",
                DependencyKind::Build,
                &mut out.dependencies,
            );
        }
    }

    Ok(out)
}

fn extract_deps(
    value: &toml::Value,
    section: &str,
    kind: DependencyKind,
    out: &mut Vec<Dependency>,
) {
    let Some(table) = value.get(section).and_then(toml::Value::as_table) else {
        return;
    };
    for (name, dep) in table {
        let (version_req, optional) = match dep {
            toml::Value::String(v) => (Some(v.clone()), false),
            toml::Value::Table(t) => {
                let v = t
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string);
                let opt = t
                    .get("optional")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false);
                (v, opt)
            }
            _ => (None, false),
        };
        out.push(Dependency {
            name: name.clone(),
            version_req,
            optional,
            kind,
        });
    }
}

/// Parse a `tauri.conf.json` (Tauri v1 or v2). Tolerant of unknown keys.
///
/// # Errors
///
/// Returns an error if the input is not valid JSON.
pub fn parse_tauri_conf(raw: &str) -> Result<TauriManifest> {
    use serde_json::Value;

    let v: Value = serde_json::from_str(raw).context("not valid JSON")?;

    let product_name = v
        .pointer("/productName")
        .or_else(|| v.pointer("/package/productName"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let version = v
        .pointer("/version")
        .or_else(|| v.pointer("/package/version"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let csp_value = v
        .pointer("/app/security/csp")
        .or_else(|| v.pointer("/tauri/security/csp"));
    let csp_disabled = matches!(csp_value, Some(Value::Null));

    let mut allowlist: Vec<String> = Vec::new();
    if let Some(Value::Object(allow)) = v.pointer("/tauri/allowlist") {
        for (k, vv) in allow {
            if k == "all" {
                if vv.as_bool() == Some(true) {
                    allowlist.push("all".to_string());
                }
                continue;
            }
            if let Value::Object(sub) = vv {
                for (sk, sv) in sub {
                    if sv.as_bool() == Some(true) {
                        allowlist.push(format!("{k}.{sk}"));
                    }
                }
            } else if vv.as_bool() == Some(true) {
                allowlist.push(k.clone());
            }
        }
        allowlist.sort();
    }

    let mut features: Vec<String> = Vec::new();
    if let Some(Value::Object(plugins)) = v.pointer("/plugins") {
        for k in plugins.keys() {
            features.push(format!("plugin:{k}"));
        }
    }
    if let Some(Value::Array(caps)) = v.pointer("/app/security/capabilities") {
        for c in caps {
            if let Some(s) = c.as_str() {
                features.push(format!("capability:{s}"));
            }
        }
    }
    features.sort();
    features.dedup();

    Ok(TauriManifest {
        product_name,
        version,
        features,
        csp_disabled,
        allowlist,
    })
}

fn is_ignored(path: &Path) -> bool {
    const SKIP: &[&str] = &[
        "target",
        "node_modules",
        ".git",
        "dist",
        "build",
        ".next",
        ".svelte-kit",
        "out",
        ".DS_Store",
    ];
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| SKIP.contains(&n))
}

fn relativize(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root)
        .map_or_else(|_| path.to_path_buf(), Path::to_path_buf)
}

fn root_name(root: &Path) -> String {
    root.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

impl DependencyKind {
    fn cmp_kind(self, other: DependencyKind) -> std::cmp::Ordering {
        (self as u8).cmp(&(other as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cargo_toml_extracts_basic_deps() {
        let raw = r#"
            [package]
            name = "my-app"
            version = "0.2.1"

            [dependencies]
            serde = "1.0"
            tokio = { version = "1.38", features = ["full"] }
            local-thing = { path = "../local" }

            [dev-dependencies]
            tempfile = "3.8"

            [build-dependencies]
            cc = "1.0"
        "#;
        let parsed = parse_cargo_toml(raw).unwrap();
        assert_eq!(parsed.crate_name.as_deref(), Some("my-app"));
        assert_eq!(parsed.crate_version.as_deref(), Some("0.2.1"));

        let names: Vec<_> = parsed
            .dependencies
            .iter()
            .map(|d| (d.name.as_str(), d.kind))
            .collect();
        assert!(names.contains(&("serde", DependencyKind::Normal)));
        assert!(names.contains(&("tokio", DependencyKind::Normal)));
        assert!(names.contains(&("local-thing", DependencyKind::Normal)));
        assert!(names.contains(&("tempfile", DependencyKind::Dev)));
        assert!(names.contains(&("cc", DependencyKind::Build)));

        let tokio = parsed
            .dependencies
            .iter()
            .find(|d| d.name == "tokio")
            .unwrap();
        assert_eq!(tokio.version_req.as_deref(), Some("1.38"));

        let local = parsed
            .dependencies
            .iter()
            .find(|d| d.name == "local-thing")
            .unwrap();
        assert_eq!(local.version_req, None);
    }

    #[test]
    fn parse_cargo_toml_handles_optional_and_target_specific() {
        let raw = r#"
            [package]
            name = "x"
            version = "0.1.0"

            [dependencies]
            opt-dep = { version = "1.0", optional = true }

            [target.'cfg(windows)'.dependencies]
            winapi = "0.3"
        "#;
        let parsed = parse_cargo_toml(raw).unwrap();
        let opt = parsed
            .dependencies
            .iter()
            .find(|d| d.name == "opt-dep")
            .unwrap();
        assert!(opt.optional);
        assert!(parsed.dependencies.iter().any(|d| d.name == "winapi"));
    }

    #[test]
    fn parse_cargo_toml_rejects_invalid_toml() {
        let err = parse_cargo_toml("[[[invalid").unwrap_err();
        assert!(err.to_string().contains("not valid TOML"));
    }

    #[test]
    fn parse_tauri_conf_v2_basic() {
        let raw = r#"{
            "productName": "Demo",
            "version": "0.3.0",
            "app": {
                "security": {
                    "csp": null,
                    "capabilities": ["main-capability", "fs-read"]
                }
            },
            "plugins": {
                "fs": {},
                "shell": {}
            }
        }"#;
        let m = parse_tauri_conf(raw).unwrap();
        assert_eq!(m.product_name.as_deref(), Some("Demo"));
        assert_eq!(m.version.as_deref(), Some("0.3.0"));
        assert!(m.csp_disabled);
        assert!(m.features.contains(&"plugin:fs".to_string()));
        assert!(m.features.contains(&"plugin:shell".to_string()));
        assert!(m
            .features
            .contains(&"capability:main-capability".to_string()));
    }

    #[test]
    fn parse_tauri_conf_v1_allowlist() {
        let raw = r#"{
            "package": { "productName": "Old", "version": "1.0.0" },
            "tauri": {
                "allowlist": {
                    "all": false,
                    "fs": { "readFile": true, "writeFile": false },
                    "shell": { "open": true }
                },
                "security": { "csp": "default-src 'self'" }
            }
        }"#;
        let m = parse_tauri_conf(raw).unwrap();
        assert_eq!(m.product_name.as_deref(), Some("Old"));
        assert_eq!(m.version.as_deref(), Some("1.0.0"));
        assert!(!m.csp_disabled);
        assert!(m.allowlist.contains(&"fs.readFile".to_string()));
        assert!(m.allowlist.contains(&"shell.open".to_string()));
        assert!(!m.allowlist.contains(&"fs.writeFile".to_string()));
    }

    #[test]
    fn parse_project_aggregates_workspace_members() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"b\"]\n",
        )
        .unwrap();

        std::fs::create_dir_all(root.join("a/src")).unwrap();
        std::fs::write(
            root.join("a/Cargo.toml"),
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"\n",
        )
        .unwrap();
        std::fs::write(root.join("a/src/lib.rs"), "").unwrap();

        std::fs::create_dir_all(root.join("b/src")).unwrap();
        std::fs::write(
            root.join("b/Cargo.toml"),
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n[dependencies]\nanyhow = \"1.0\"\n",
        )
        .unwrap();
        std::fs::write(root.join("b/src/lib.rs"), "").unwrap();

        // Skipped directory.
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(
            root.join("target/Cargo.toml"),
            "[package]\nname = \"should-be-ignored\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();

        let parsed = parse_project(root).unwrap();
        let names: Vec<_> = parsed
            .dependencies
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"anyhow"));
        assert!(!parsed
            .dependencies
            .iter()
            .any(|d| d.name == "should-be-ignored"));
    }

    #[test]
    fn parse_project_errors_when_no_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let err = parse_project(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("no Cargo.toml"));
    }
}
