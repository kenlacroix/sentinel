//! Shared scan helpers used by every Sentinel tool that walks a project
//! source tree.
//!
//! Centralising the directory ignore list here avoids the silent-divergence
//! risk where one tool descends into `target/` while another doesn't, which
//! would produce inconsistent reports for the same project.

use std::path::Path;

/// Directory basenames every Sentinel tool skips during a scan.
///
/// These never contain meaningful source for an audit:
///
/// - `target/` — Rust build cache (gigabytes of generated `.rs` and binaries)
/// - `node_modules/` — JS dependency tree (millions of files, untrusted)
/// - `.git/` — version control internals
/// - `dist/`, `build/`, `out/` — bundler output
/// - `.next/`, `.svelte-kit/` — framework caches
/// - `.DS_Store` — macOS Finder metadata file
pub const DEFAULT_IGNORED_DIRS: &[&str] = &[
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

/// Returns `true` if `path`'s basename matches one of [`DEFAULT_IGNORED_DIRS`].
///
/// Used as a `walkdir::WalkDir::filter_entry` predicate to prune entire
/// subtrees rather than visiting every file inside them.
#[must_use]
pub fn is_ignored_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| DEFAULT_IGNORED_DIRS.contains(&n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn target_directory_is_ignored() {
        assert!(is_ignored_path(Path::new("/some/project/target")));
        assert!(is_ignored_path(Path::new("target")));
    }

    #[test]
    fn source_directories_are_not_ignored() {
        for name in ["src", "lib", "components", "api"] {
            assert!(
                !is_ignored_path(Path::new(name)),
                "{name} should not be ignored"
            );
        }
    }

    #[test]
    fn each_default_basename_is_ignored() {
        for d in DEFAULT_IGNORED_DIRS {
            assert!(is_ignored_path(Path::new(d)), "{d} should be ignored");
        }
    }
}
