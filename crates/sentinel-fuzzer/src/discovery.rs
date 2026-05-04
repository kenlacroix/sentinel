//! Discover user-authored fuzz targets in a project's `fuzz/` subcrate.
//!
//! We follow the [cargo-fuzz convention](https://rust-fuzz.github.io/book/cargo-fuzz.html):
//!
//! ```text
//! <project>/
//! └── fuzz/
//!     ├── Cargo.toml
//!     └── fuzz_targets/
//!         ├── store_mood.rs
//!         └── sync_to_watch.rs
//! ```
//!
//! Each `*.rs` file under `fuzz_targets/` is one fuzz target. The target name
//! is the filename stem.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A fuzz target Sentinel can drive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FuzzTarget {
    /// Logical name (e.g. `store_mood`), suitable for the CLI `--target` flag.
    pub name: String,
    /// Absolute path to the target's source file.
    pub source_path: PathBuf,
}

/// Discover all fuzz targets in `project_root/fuzz/fuzz_targets/`.
///
/// Returns `Ok(vec![])` (not an error) when the `fuzz/` directory is missing,
/// since "no fuzz targets" is a normal state for a freshly-cloned project.
/// The error path is reserved for cases where the directory exists but is
/// malformed in some way that should fail loudly.
///
/// # Errors
///
/// Returns an error if `project_root` does not exist or cannot be canonicalized.
pub fn discover_targets(project_root: &Path) -> Result<Vec<FuzzTarget>> {
    let root = project_root
        .canonicalize()
        .with_context(|| format!("project root does not exist: {}", project_root.display()))?;
    let targets_dir = root.join("fuzz").join("fuzz_targets");
    if !targets_dir.is_dir() {
        return Ok(vec![]);
    }

    let mut found: Vec<FuzzTarget> = Vec::new();
    for entry in std::fs::read_dir(&targets_dir).with_context(|| {
        format!(
            "failed to read fuzz_targets directory: {}",
            targets_dir.display()
        )
    })? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        // Skip obviously-bogus filenames.
        if stem.is_empty() || stem.starts_with('.') {
            continue;
        }
        found.push(FuzzTarget {
            name: stem.to_string(),
            source_path: path,
        });
    }

    found.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(found)
}

/// The directory `cargo fuzz` should be invoked from, given a project root.
///
/// This is just `<project_root>/fuzz`, but exposing it as a function keeps
/// the convention pinned in one place.
#[must_use]
pub fn fuzz_crate_root(project_root: &Path) -> PathBuf {
    project_root.join("fuzz")
}

/// Where libFuzzer artifacts are written for a given target.
#[must_use]
pub fn artifacts_dir(project_root: &Path, target: &str) -> PathBuf {
    project_root.join("fuzz").join("artifacts").join(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_project(tmp: &Path, target_files: &[&str]) {
        let dir = tmp.join("fuzz").join("fuzz_targets");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            tmp.join("fuzz").join("Cargo.toml"),
            "[package]\nname = \"my-fuzz\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        for f in target_files {
            std::fs::write(dir.join(f), "// fuzz target\n").unwrap();
        }
    }

    #[test]
    fn returns_empty_vec_when_fuzz_dir_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let targets = discover_targets(tmp.path()).unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn errors_when_project_root_does_not_exist() {
        let err =
            discover_targets(Path::new("/definitely/does/not/exist/sentinel-test")).unwrap_err();
        assert!(err.to_string().contains("project root does not exist"));
    }

    #[test]
    fn discovers_rs_files_and_sorts_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        make_project(tmp.path(), &["zebra.rs", "alpha.rs", "middle.rs"]);
        let targets = discover_targets(tmp.path()).unwrap();
        let names: Vec<_> = targets.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn ignores_non_rs_files_and_dotfiles() {
        let tmp = tempfile::tempdir().unwrap();
        make_project(
            tmp.path(),
            &["real.rs", "README.md", ".hidden.rs", "Cargo.lock"],
        );
        let names: Vec<_> = discover_targets(tmp.path())
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["real".to_string()]);
    }

    #[test]
    fn ignores_subdirectories_inside_fuzz_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("fuzz").join("fuzz_targets");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(dir.join("nested")).unwrap();
        std::fs::write(dir.join("nested").join("inner.rs"), "// nested").unwrap();
        std::fs::write(dir.join("real.rs"), "// real").unwrap();
        let names: Vec<_> = discover_targets(tmp.path())
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["real".to_string()]);
    }

    #[test]
    fn fuzz_crate_root_and_artifacts_dir_match_convention() {
        let p = Path::new("/tmp/proj");
        assert_eq!(fuzz_crate_root(p), Path::new("/tmp/proj/fuzz"));
        assert_eq!(
            artifacts_dir(p, "store_mood"),
            Path::new("/tmp/proj/fuzz/artifacts/store_mood")
        );
    }
}
