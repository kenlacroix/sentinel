//! Toolchain diagnostics for the unified CLI.
//!
//! Each Sentinel tool depends on different parts of the system. The
//! `doctor` command checks all of them in one pass so the user knows
//! exactly what to install before running a scan.

use std::process::Command;

/// One diagnostic check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Human-readable label (e.g. "cargo-fuzz").
    pub label: &'static str,
    /// Which tool this check is required by.
    pub required_for: &'static str,
    /// Whether the dependency is present.
    pub ok: bool,
    /// Install hint when missing.
    pub fix_hint: &'static str,
}

/// Run every diagnostic check and return them in display order.
#[must_use]
pub fn run_all_checks() -> Vec<Check> {
    vec![
        check_rustc(),
        check_cargo(),
        check_cargo_fuzz(),
        check_nightly(),
        check_tar(),
    ]
}

/// Returns true if every check passed.
#[must_use]
pub fn all_ok(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.ok)
}

fn check_rustc() -> Check {
    Check {
        label: "rustc",
        required_for: "all tools",
        ok: bin_runs("rustc", &["--version"]),
        fix_hint: "Install via https://rustup.rs",
    }
}

fn check_cargo() -> Check {
    Check {
        label: "cargo",
        required_for: "all tools",
        ok: bin_runs("cargo", &["--version"]),
        fix_hint: "Comes with rustup; reinstall via https://rustup.rs",
    }
}

fn check_cargo_fuzz() -> Check {
    Check {
        label: "cargo-fuzz",
        required_for: "fuzzer",
        ok: bin_runs("cargo", &["fuzz", "--version"]),
        fix_hint: "cargo install cargo-fuzz",
    }
}

fn check_nightly() -> Check {
    Check {
        label: "nightly toolchain",
        required_for: "fuzzer",
        ok: rustup_has_nightly(),
        fix_hint: "rustup toolchain install nightly",
    }
}

fn check_tar() -> Check {
    Check {
        label: "tar",
        required_for: "cartographer (advisory archive)",
        ok: bin_runs("tar", &["--version"]),
        fix_hint: "apt-get install tar  (Linux) | brew install gnu-tar  (macOS)",
    }
}

fn bin_runs(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn rustup_has_nightly() -> bool {
    Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("nightly"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_all_checks_returns_one_per_dependency() {
        let checks = run_all_checks();
        assert_eq!(checks.len(), 5);
        let labels: Vec<&str> = checks.iter().map(|c| c.label).collect();
        assert!(labels.contains(&"rustc"));
        assert!(labels.contains(&"cargo"));
        assert!(labels.contains(&"cargo-fuzz"));
        assert!(labels.contains(&"nightly toolchain"));
        assert!(labels.contains(&"tar"));
    }

    #[test]
    fn each_check_has_a_fix_hint() {
        for c in run_all_checks() {
            assert!(!c.fix_hint.is_empty(), "{} lacks a fix hint", c.label);
        }
    }
}
