//! Filesystem helpers shared across Sentinel tools.
//!
//! Centralises path resolution for the on-disk cache and report directories
//! so each tool agrees on `~/.sentinel/...`.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Returns the root directory Sentinel uses for caches and reports.
///
/// Defaults to `$HOME/.sentinel`. The `SENTINEL_HOME` environment variable
/// overrides this for tests and CI.
///
/// # Errors
///
/// Returns an error if the home directory cannot be located on this platform
/// and `SENTINEL_HOME` is not set.
pub fn sentinel_home() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("SENTINEL_HOME") {
        return Ok(PathBuf::from(custom));
    }
    let home = dirs_home_dir()
        .context("could not locate the user home directory; set SENTINEL_HOME to override")?;
    Ok(home.join(".sentinel"))
}

/// Ensures `path` exists as a directory, creating intermediate components.
///
/// # Errors
///
/// Returns an error if any parent directory cannot be created.
pub fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create directory: {}", path.display()))
}

fn dirs_home_dir() -> Option<PathBuf> {
    // We deliberately avoid pulling the `dirs` crate into sentinel-core to
    // keep the dependency graph lean — falling back to platform env vars
    // covers Linux, macOS, and Windows for this use case.
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_home_respects_env_override() {
        let tmp = tempfile_path();
        std::env::set_var("SENTINEL_HOME", &tmp);
        let resolved = sentinel_home().unwrap();
        assert_eq!(resolved, PathBuf::from(&tmp));
        std::env::remove_var("SENTINEL_HOME");
    }

    #[test]
    fn ensure_dir_creates_nested_paths() {
        let base = std::env::temp_dir().join(format!("sentinel-test-{}", std::process::id()));
        let nested = base.join("a").join("b").join("c");
        ensure_dir(&nested).unwrap();
        assert!(nested.is_dir());
        let _ = std::fs::remove_dir_all(&base);
    }

    fn tempfile_path() -> String {
        std::env::temp_dir()
            .join(format!("sentinel-home-{}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }
}
