//! Convert parsed [`CrashInfo`] records into `sentinel_core::Finding`s.
//!
//! A single fuzz run can produce many crashes that all share a root cause —
//! libFuzzer dedups inputs by bytes, but two byte-different inputs can hit
//! the same panic. We dedup again at the **panic-location + top-frame**
//! level so the user sees one finding per real bug.

use std::fmt::Write;

use sentinel_core::{Finding, Location, Severity, Tool};
use sha2::{Digest, Sha256};

use crate::parse::{CrashInfo, CrashKind, SourceLocation};

/// Convert a parsed crash into a normalized [`Finding`].
///
/// `target` is the fuzz-target name (e.g. `store_mood`); used in the finding's
/// component string and id.
#[must_use]
pub fn crash_to_finding(target: &str, info: &CrashInfo) -> Finding {
    let dedup_hash = dedup_hash(info);
    let id = format!("fuzzer.crash.{}.{}", info.kind.tag(), &dedup_hash[..12]);

    Finding {
        id,
        title: build_title(target, info),
        description: build_description(target, info),
        severity: severity_for(info.kind),
        tool: Tool::Fuzzer,
        component: format!("fuzz_target:{target}"),
        suggestion: build_suggestion(info),
        location: info.location.as_ref().map(location_to_core),
        references: build_references(info),
    }
}

/// Deduplicate findings by id, keeping the first occurrence.
///
/// Findings are sorted by severity (highest first) then by id.
#[must_use]
pub fn dedup_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    let mut seen: Vec<String> = Vec::with_capacity(findings.len());
    findings.retain(|f| {
        if seen.iter().any(|s| s == &f.id) {
            false
        } else {
            seen.push(f.id.clone());
            true
        }
    });
    findings
}

fn build_title(target: &str, info: &CrashInfo) -> String {
    match info.kind {
        CrashKind::Panic => format!("Panic in {target}: {}", clip(&info.summary, 80)),
        CrashKind::Sanitizer => {
            format!("Sanitizer report in {target}: {}", clip(&info.summary, 80))
        }
        CrashKind::Oom => format!("Out-of-memory in {target}"),
        CrashKind::Timeout => format!("Timeout in {target}"),
        CrashKind::DeadlySignal => format!("Deadly signal in {target}"),
        CrashKind::Unknown => format!("Unclassified crash in {target}"),
    }
}

fn build_description(target: &str, info: &CrashInfo) -> String {
    let mut s = format!(
        "The fuzz target `{target}` produced a {kind} crash.",
        kind = info.kind.tag()
    );
    if !info.summary.is_empty() {
        s.push_str("\n\nMessage: ");
        s.push_str(&info.summary);
    }
    if let Some(loc) = info.location.as_ref() {
        let _ = write!(s, "\n\nLocation: {}:{}", loc.file, loc.line);
    }
    if let Some(frame) = info.top_frame.as_ref() {
        s.push_str("\n\nTop user frame: ");
        s.push_str(frame);
    }
    if let Some(artifact) = info.artifact_path.as_ref() {
        let _ = write!(
            s,
            "\n\nReproduce with:\n  cargo +nightly fuzz run {target} {artifact}",
        );
    }
    if !info.raw_excerpt.is_empty() {
        s.push_str("\n\nlibFuzzer stderr (excerpt):\n");
        s.push_str(&info.raw_excerpt);
    }
    s
}

fn build_suggestion(info: &CrashInfo) -> String {
    match info.kind {
        CrashKind::Panic => {
            "Treat panics in IPC handlers as exploitable: add input validation upstream of \
             the panicking code path and return a structured error to the webview instead."
                .to_string()
        }
        CrashKind::Sanitizer => {
            "Sanitizer reports indicate memory unsafety in `unsafe` Rust or a C/C++ \
             dependency. Audit the offending function and add a focused unit test for the \
             reproducer input."
                .to_string()
        }
        CrashKind::Oom => {
            "Constrain input sizes at the IPC boundary; consider a max-payload check and \
             streaming for large inputs to avoid resource exhaustion."
                .to_string()
        }
        CrashKind::Timeout => {
            "Bound the worst-case complexity of this handler. Add a hard deadline or move \
             expensive work to a background task."
                .to_string()
        }
        CrashKind::DeadlySignal | CrashKind::Unknown => {
            "Reproduce the crash locally with the saved artifact, capture a backtrace with \
             `RUST_BACKTRACE=full`, and triage from there."
                .to_string()
        }
    }
}

fn build_references(info: &CrashInfo) -> Vec<String> {
    let mut refs = Vec::new();
    refs.push("https://rust-fuzz.github.io/book/cargo-fuzz.html".to_string());
    if matches!(info.kind, CrashKind::Sanitizer) {
        refs.push("https://github.com/google/sanitizers/wiki/AddressSanitizer".to_string());
    }
    refs
}

fn location_to_core(loc: &SourceLocation) -> Location {
    Location::new(loc.file.clone(), Some(loc.line))
}

/// Severity inference rationale:
///
/// - **Panic** in an IPC handler is reachable by anyone who can talk to the
///   webview (i.e. compromised frontend code, malicious extension). Treat as
///   `High`: deterministic remote `DoS` at minimum, often exploitable for
///   logic bypass.
/// - **Sanitizer** reports usually mean memory corruption — `Critical`.
/// - **OOM / timeout** are resource exhaustion → `Medium` (`DoS` but not RCE).
/// - **Deadly signal** without a panic line is rare; default to `High`.
/// - **Unknown** → `Medium`, since we don't know what we caught.
fn severity_for(kind: CrashKind) -> Severity {
    match kind {
        CrashKind::Sanitizer => Severity::Critical,
        CrashKind::Panic | CrashKind::DeadlySignal => Severity::High,
        CrashKind::Oom | CrashKind::Timeout | CrashKind::Unknown => Severity::Medium,
    }
}

/// Hex-encoded SHA-256 of a normalized crash signature: `kind | location | top_frame | summary`.
///
/// Inputs that hit the same panic line in the same function should produce
/// the same hash even when their bytes differ.
fn dedup_hash(info: &CrashInfo) -> String {
    let mut h = Sha256::new();
    h.update(info.kind.tag().as_bytes());
    h.update(b"|");
    if let Some(loc) = info.location.as_ref() {
        h.update(loc.file.as_bytes());
        h.update(b":");
        h.update(loc.line.to_string().as_bytes());
    }
    h.update(b"|");
    if let Some(frame) = info.top_frame.as_ref() {
        h.update(normalize_frame(frame).as_bytes());
    }
    h.update(b"|");
    // Summary is a fallback signal — many panics differ only in this string,
    // and we still want them deduped when location+frame are absent.
    h.update(info.summary.as_bytes());
    hex::encode(h.finalize())
}

/// Strip address-y noise and demangling-instance suffixes so that two frames
/// from different runs hash to the same value.
fn normalize_frame(frame: &str) -> String {
    // Drop trailing `::h<hex>` rustc-instance hashes.
    let no_hash = if let Some(idx) = frame.rfind("::h") {
        let tail = &frame[idx + 3..];
        if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_hexdigit()) {
            &frame[..idx]
        } else {
            frame
        }
    } else {
        frame
    };
    no_hash.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut truncated: String = s.chars().take(max - 1).collect();
        truncated.push('…');
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panic_info(file: &str, line: u32, frame: &str, msg: &str) -> CrashInfo {
        CrashInfo {
            kind: CrashKind::Panic,
            summary: msg.to_string(),
            location: Some(SourceLocation {
                file: file.to_string(),
                line,
                column: Some(5),
            }),
            top_frame: Some(frame.to_string()),
            artifact_path: Some("./crash-abc123".to_string()),
            raw_excerpt: "thread 'main' panicked at 'oops', src/lib.rs:1:1".to_string(),
        }
    }

    #[test]
    fn panic_becomes_high_severity_finding() {
        let info = panic_info("src/lib.rs", 42, "my::handler", "boom");
        let f = crash_to_finding("store_mood", &info);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.tool, Tool::Fuzzer);
        assert_eq!(f.component, "fuzz_target:store_mood");
        assert!(f.id.starts_with("fuzzer.crash.panic."));
        assert_eq!(
            f.location.as_ref().map(|l| l.file.as_str()),
            Some("src/lib.rs")
        );
        assert_eq!(f.location.and_then(|l| l.line), Some(42));
    }

    #[test]
    fn sanitizer_becomes_critical() {
        let info = CrashInfo {
            kind: CrashKind::Sanitizer,
            summary: "heap-buffer-overflow".to_string(),
            location: None,
            top_frame: Some("vulnerable_fn".to_string()),
            artifact_path: None,
            raw_excerpt: String::new(),
        };
        let f = crash_to_finding("t", &info);
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn oom_and_timeout_are_medium() {
        for kind in [CrashKind::Oom, CrashKind::Timeout] {
            let info = CrashInfo {
                kind,
                summary: "x".to_string(),
                location: None,
                top_frame: None,
                artifact_path: None,
                raw_excerpt: String::new(),
            };
            let f = crash_to_finding("t", &info);
            assert_eq!(f.severity, Severity::Medium, "{kind:?}");
        }
    }

    #[test]
    fn dedup_collapses_same_panic_location() {
        let a = panic_info("src/lib.rs", 42, "my::handler::h1234aaaa", "boom A");
        let b = panic_info("src/lib.rs", 42, "my::handler::h1234bbbb", "boom A");
        // Same location + same normalized frame + same summary → same id.
        let fa = crash_to_finding("t", &a);
        let fb = crash_to_finding("t", &b);
        assert_eq!(
            fa.id, fb.id,
            "expected dedup hash to ignore rustc-instance suffix"
        );

        let deduped = dedup_findings(vec![fa.clone(), fb]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].id, fa.id);
    }

    #[test]
    fn dedup_keeps_distinct_panics() {
        let a = panic_info("src/lib.rs", 42, "fn_a", "boom");
        let b = panic_info("src/lib.rs", 99, "fn_b", "boom");
        let deduped = dedup_findings(vec![crash_to_finding("t", &a), crash_to_finding("t", &b)]);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn dedup_sorts_critical_above_high() {
        let panic = panic_info("a.rs", 1, "f", "p");
        let san = CrashInfo {
            kind: CrashKind::Sanitizer,
            summary: "uaf".to_string(),
            location: None,
            top_frame: None,
            artifact_path: None,
            raw_excerpt: String::new(),
        };
        let findings = vec![crash_to_finding("t", &panic), crash_to_finding("t", &san)];
        let sorted = dedup_findings(findings);
        assert_eq!(sorted[0].severity, Severity::Critical);
        assert_eq!(sorted[1].severity, Severity::High);
    }

    #[test]
    fn description_includes_reproduce_command() {
        let info = panic_info("src/lib.rs", 1, "f", "x");
        let f = crash_to_finding("store_mood", &info);
        assert!(f
            .description
            .contains("cargo +nightly fuzz run store_mood ./crash-abc123"));
    }

    #[test]
    fn normalize_frame_strips_rustc_hash_suffix() {
        assert_eq!(normalize_frame("foo::bar::h1234abcd"), "foo::bar");
        // Non-hex tail is left alone.
        assert_eq!(normalize_frame("foo::bar::happy"), "foo::bar::happy");
    }
}
