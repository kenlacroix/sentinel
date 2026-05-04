//! Parse libFuzzer / cargo-fuzz stderr output into structured crash records.
//!
//! libFuzzer produces a small handful of distinct crash genres, each with a
//! recognisable stderr signature. This module is deliberately tolerant — when
//! a field is missing or the format drifts slightly, we fall back to
//! conservative defaults rather than fail to report a crash.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// What kind of crash libFuzzer reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrashKind {
    /// Rust panic (most common — `panic!()`, unwrap on `None`, index out of bounds, ...).
    Panic,
    /// Address-/memory-sanitizer report (use-after-free, buffer overflow, ...).
    Sanitizer,
    /// libFuzzer reported an out-of-memory event.
    Oom,
    /// libFuzzer reported a timeout (input took longer than `-timeout`).
    Timeout,
    /// Deadly signal (SIGSEGV, SIGABRT) without a parseable Rust panic line.
    DeadlySignal,
    /// We saw evidence of a crash but couldn't classify it.
    Unknown,
}

impl CrashKind {
    /// Single-word lowercase tag suitable for finding ids.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            CrashKind::Panic => "panic",
            CrashKind::Sanitizer => "sanitizer",
            CrashKind::Oom => "oom",
            CrashKind::Timeout => "timeout",
            CrashKind::DeadlySignal => "signal",
            CrashKind::Unknown => "unknown",
        }
    }
}

/// Structured crash info extracted from libFuzzer stderr.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashInfo {
    /// Classification of the crash.
    pub kind: CrashKind,
    /// First-line summary suitable for a finding title (e.g. the panic
    /// message, or the sanitizer error name).
    pub summary: String,
    /// Source location parsed from a Rust panic line, when present.
    pub location: Option<SourceLocation>,
    /// First demangled stack frame above the libFuzzer machinery, when found.
    pub top_frame: Option<String>,
    /// Path to the artifact file libFuzzer wrote, relative to the working
    /// directory of the original `cargo fuzz run`. Useful for reproducing.
    pub artifact_path: Option<String>,
    /// Raw stderr lines we considered "diagnostic" — useful for the report.
    pub raw_excerpt: String,
}

/// Source file + line + column from a Rust panic line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Source file, as written in the panic message.
    pub file: String,
    /// 1-indexed line number.
    pub line: u32,
    /// 1-indexed column number, when present.
    pub column: Option<u32>,
}

/// Parse libFuzzer stderr (typically captured from `cargo fuzz run`) into
/// a [`CrashInfo`]. Returns `None` if no crash signature is detected.
#[must_use]
pub fn parse_libfuzzer_stderr(stderr: &str) -> Option<CrashInfo> {
    let kind = detect_kind(stderr)?;

    let panic = parse_panic(stderr);
    let summary = panic
        .as_ref()
        .map(|p| p.message.clone())
        .or_else(|| sanitizer_summary(stderr))
        .or_else(|| libfuzzer_summary(stderr))
        .unwrap_or_else(|| match kind {
            CrashKind::Oom => "out-of-memory".to_string(),
            CrashKind::Timeout => "timeout".to_string(),
            CrashKind::DeadlySignal => "deadly signal (no panic message)".to_string(),
            CrashKind::Sanitizer => "sanitizer report".to_string(),
            _ => "unknown crash".to_string(),
        });

    let location = panic
        .and_then(|p| p.location)
        .or_else(|| sanitizer_location(stderr));

    let top_frame = top_user_frame(stderr);

    let artifact_path = artifact_re()
        .captures(stderr)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string());

    let raw_excerpt = extract_excerpt(stderr);

    Some(CrashInfo {
        kind,
        summary,
        location,
        top_frame,
        artifact_path,
        raw_excerpt,
    })
}

struct PanicMatch {
    message: String,
    location: Option<SourceLocation>,
}

/// Parse a Rust panic line. Handles both formats:
///
/// - Legacy: `thread '...' panicked at 'message', file.rs:LINE[:COL]`
/// - Modern: `thread '...' panicked at file.rs:LINE[:COL]:\nmessage`
fn parse_panic(stderr: &str) -> Option<PanicMatch> {
    static LEGACY: OnceLock<Regex> = OnceLock::new();
    static MODERN: OnceLock<Regex> = OnceLock::new();

    let legacy = LEGACY.get_or_init(|| {
        Regex::new(
            r"thread '[^']*' panicked at '([^']*)',\s*([A-Za-z0-9_./\-\\]+\.rs):(\d+)(?::(\d+))?",
        )
        .expect("legacy panic re")
    });
    if let Some(caps) = legacy.captures(stderr) {
        return Some(PanicMatch {
            message: caps[1].to_string(),
            location: parse_loc(&caps, 2, 3, 4),
        });
    }

    let modern = MODERN.get_or_init(|| {
        Regex::new(
            r"thread '[^']*' panicked at ([A-Za-z0-9_./\-\\]+\.rs):(\d+)(?::(\d+))?:\s*\n([^\n]+)",
        )
        .expect("modern panic re")
    });
    if let Some(caps) = modern.captures(stderr) {
        return Some(PanicMatch {
            message: caps[4].trim().to_string(),
            location: parse_loc(&caps, 1, 2, 3),
        });
    }

    None
}

fn parse_loc(
    caps: &regex::Captures,
    file_idx: usize,
    line_idx: usize,
    col_idx: usize,
) -> Option<SourceLocation> {
    let file = caps.get(file_idx)?.as_str().to_string();
    let line: u32 = caps.get(line_idx)?.as_str().parse().ok()?;
    let column: Option<u32> = caps.get(col_idx).and_then(|m| m.as_str().parse().ok());
    Some(SourceLocation { file, line, column })
}

/// When the parsed crash is a sanitizer report, the location often appears
/// inline on the SUMMARY line (`SUMMARY: AddressSanitizer: ... /file.rs:21:9 in ...`).
fn sanitizer_location(stderr: &str) -> Option<SourceLocation> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"SUMMARY:[^\n]*?([A-Za-z0-9_./\-\\]+\.rs):(\d+)(?::(\d+))?")
            .expect("sanitizer loc re")
    });
    re.captures(stderr)
        .and_then(|caps| parse_loc(&caps, 1, 2, 3))
}

fn detect_kind(stderr: &str) -> Option<CrashKind> {
    let s = stderr;
    if s.contains("libFuzzer: out-of-memory") || s.contains("ERROR: libFuzzer: out-of-memory") {
        return Some(CrashKind::Oom);
    }
    if s.contains("libFuzzer: timeout") || s.contains("ERROR: libFuzzer: timeout") {
        return Some(CrashKind::Timeout);
    }
    let has_sanitizer = s.contains("AddressSanitizer")
        || s.contains("MemorySanitizer")
        || s.contains("UndefinedBehaviorSanitizer")
        || s.contains("LeakSanitizer")
        || s.contains("ThreadSanitizer");
    if has_sanitizer {
        return Some(CrashKind::Sanitizer);
    }
    if parse_panic(s).is_some() {
        return Some(CrashKind::Panic);
    }
    if s.contains("libFuzzer: deadly signal") {
        return Some(CrashKind::DeadlySignal);
    }
    if s.contains("ERROR: libFuzzer") || s.contains("SUMMARY: libFuzzer") {
        return Some(CrashKind::Unknown);
    }
    None
}

fn artifact_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"Test unit written to\s+(\S+)").expect("artifact_re"))
}

fn sanitizer_summary(stderr: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"==\d+==ERROR:\s*([^\n]+)").expect("sanitizer_re"));
    re.captures(stderr)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
}

fn libfuzzer_summary(stderr: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re =
        RE.get_or_init(|| Regex::new(r"SUMMARY:\s*libFuzzer:\s*([^\n]+)").expect("summary_re"));
    re.captures(stderr)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
}

/// Extract the first stack frame that doesn't look like libFuzzer / runtime
/// machinery, for use as a dedup key.
fn top_user_frame(stderr: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?m)^\s*#\d+\s+(?:0x[0-9a-fA-F]+\s+)?(?:in\s+)?(.+?)(?:\s+at\s+|\s*$)")
            .expect("frame_re")
    });
    for caps in re.captures_iter(stderr) {
        let Some(frame) = caps.get(1).map(|m| m.as_str().trim().to_string()) else {
            continue;
        };
        if is_machinery_frame(&frame) {
            continue;
        }
        return Some(frame);
    }
    None
}

fn is_machinery_frame(frame: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "__sanitizer",
        "fuzzer::",
        "LLVMFuzzer",
        "rust_begin_unwind",
        "core::panicking",
        "std::panicking",
        "core::ops::function",
        "std::sys::",
        "std::rt::",
        "_start",
        "libc_start",
    ];
    NEEDLES.iter().any(|n| frame.contains(n))
}

/// Pull out the diagnostic-looking lines (panic / SUMMARY / sanitizer / artifact)
/// for embedding in the finding. Filters out the noisy MS / mutation-stat lines.
fn extract_excerpt(stderr: &str) -> String {
    let mut keep: Vec<&str> = Vec::new();
    let mut inside_stack_block = false;
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            inside_stack_block = false;
            continue;
        }
        let is_panic = trimmed.starts_with("thread '") || trimmed.starts_with("panicked at");
        let is_summary = trimmed.starts_with("SUMMARY:") || trimmed.starts_with("==");
        let is_artifact =
            trimmed.starts_with("Test unit written") || trimmed.starts_with("artifact_prefix");
        let is_stack_frame =
            trimmed.starts_with('#') && (trimmed.contains(" 0x") || trimmed.contains(" in "));
        if is_panic || is_summary || is_artifact {
            keep.push(line);
            inside_stack_block = is_panic;
        } else if (is_stack_frame || inside_stack_block) && keep.len() < 40 {
            keep.push(line);
        }
    }
    keep.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PANIC_OUTPUT: &str = r"INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1234567890
==12345==ERROR: libFuzzer: deadly signal
    #0 0x55a in __sanitizer_print_stack_trace (...)
    #1 0x55b in fuzzer::PrintStackTrace() (...)
    #2 0x55c in core::panicking::panic_bounds_check (...)
    #3 0x55d in synthetic_target::run::h1234abcd at fuzz_targets/store_mood.rs:18:9
    #4 0x55e in rust_fuzzer_test_input (...)
thread 'main' panicked at 'index out of bounds: the len is 5 but the index is 99', src/store.rs:42:5
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
==12345== ERROR: libFuzzer: deadly signal
SUMMARY: libFuzzer: deadly signal
MS: 1 ChangeBit-; base unit: 39d8...
0x7b,0x7d,
{}
artifact_prefix='./'; Test unit written to ./crash-abc123def456789012345678
Base64: e30=
";

    const OOM_OUTPUT: &str = r"INFO: Running...
==99==ERROR: libFuzzer: out-of-memory (used: 2049Mb; limit: 2048Mb)
   To change the out-of-memory limit use -rss_limit_mb=<N>
SUMMARY: libFuzzer: out-of-memory
artifact_prefix='./'; Test unit written to ./oom-deadbeefcafe
";

    const TIMEOUT_OUTPUT: &str = r"ALARM: working on the last Unit for 25 seconds
==42==ERROR: libFuzzer: timeout after 25 seconds
SUMMARY: libFuzzer: timeout
artifact_prefix='./'; Test unit written to ./timeout-feedface
";

    const SANITIZER_OUTPUT: &str = r"==31337==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000040
READ of size 4 at 0x602000000040 thread T0
    #0 0x... in mycrate::vulnerable_fn /src/main.rs:21:9
    #1 0x... in rust_fuzzer_test_input (...)
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/main.rs:21:9 in mycrate::vulnerable_fn
artifact_prefix='./'; Test unit written to ./crash-aaaa1111
";

    #[test]
    fn returns_none_for_clean_run() {
        let stderr = "INFO: Running with entropic power schedule\nDone 1000 runs in 60s.";
        assert!(parse_libfuzzer_stderr(stderr).is_none());
    }

    #[test]
    fn parses_panic_with_message_and_location() {
        let info = parse_libfuzzer_stderr(PANIC_OUTPUT).expect("crash detected");
        assert_eq!(info.kind, CrashKind::Panic);
        assert_eq!(
            info.summary,
            "index out of bounds: the len is 5 but the index is 99"
        );
        let loc = info.location.expect("location parsed");
        assert_eq!(loc.file, "src/store.rs");
        assert_eq!(loc.line, 42);
        assert_eq!(loc.column, Some(5));
        assert_eq!(
            info.artifact_path.as_deref(),
            Some("./crash-abc123def456789012345678")
        );
        let frame = info.top_frame.expect("user frame parsed");
        assert!(frame.contains("synthetic_target::run"), "got: {frame}");
    }

    #[test]
    fn parses_oom_event() {
        let info = parse_libfuzzer_stderr(OOM_OUTPUT).expect("oom detected");
        assert_eq!(info.kind, CrashKind::Oom);
        assert!(
            info.summary.contains("out-of-memory"),
            "got: {}",
            info.summary
        );
        assert!(info.location.is_none());
        assert_eq!(info.artifact_path.as_deref(), Some("./oom-deadbeefcafe"));
    }

    #[test]
    fn parses_timeout_event() {
        let info = parse_libfuzzer_stderr(TIMEOUT_OUTPUT).expect("timeout detected");
        assert_eq!(info.kind, CrashKind::Timeout);
        assert_eq!(info.artifact_path.as_deref(), Some("./timeout-feedface"));
    }

    #[test]
    fn parses_sanitizer_report() {
        let info = parse_libfuzzer_stderr(SANITIZER_OUTPUT).expect("sanitizer detected");
        assert_eq!(info.kind, CrashKind::Sanitizer);
        assert!(
            info.summary.contains("heap-buffer-overflow"),
            "got: {}",
            info.summary
        );
        let frame = info.top_frame.expect("user frame parsed");
        assert!(frame.contains("vulnerable_fn"), "got: {frame}");
    }

    #[test]
    fn excerpt_keeps_diagnostic_lines() {
        let info = parse_libfuzzer_stderr(PANIC_OUTPUT).unwrap();
        assert!(info.raw_excerpt.contains("panicked at"));
        assert!(info.raw_excerpt.contains("SUMMARY"));
        assert!(!info.raw_excerpt.contains("INFO: Running with entropic"));
    }

    #[test]
    fn ignores_machinery_stack_frames_when_picking_top_frame() {
        let info = parse_libfuzzer_stderr(PANIC_OUTPUT).unwrap();
        let frame = info.top_frame.unwrap();
        assert!(
            !frame.contains("__sanitizer") && !frame.contains("fuzzer::"),
            "should skip machinery frames, got: {frame}"
        );
    }
}
