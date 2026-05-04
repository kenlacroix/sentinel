//! Tauri-aware dataflow tracer.
//!
//! This module implements the analyzer's main differentiating capability:
//! **trace `#[tauri::command]` arguments to known sink calls within the same
//! function body**. It is intentionally bounded to single-function scope,
//! because that's the largest scope where regex-based analysis stays
//! precise. Cross-function flow (helper functions, closures) is deferred
//! to the `analyzer.tree-sitter` Phase 2 work tracked in TODOS.md.
//!
//! ## What we model
//!
//! ```text
//! #[tauri::command]                  Source: every parameter is tainted.
//! fn run_command(input: String) {    ┌──────────────────────────────────┐
//!     let cmd = input;               │  Local rename adds `cmd` to set. │
//!     std::process::Command::new(    └──────────────────────────────────┘
//!         &cmd                       Sink: `Command::new(<arg>)` — if any
//!     )                              tainted name appears in the args, fire.
//!     .spawn();
//! }
//! ```
//!
//! ## What we don't model (yet)
//!
//! - Cross-function flow: `let x = helper(input); Command::new(x)` is missed.
//! - Closures: `(|| { Command::new(input) })()` is missed.
//! - Field access *into* the parameter (`Command::new(payload.cmd)`) is
//!   matched because the regex `\bpayload\b` hits the `payload` token in
//!   the sink call. This is correct overshoot — better than missing.
//! - Pathological brace nesting inside string literals: a `}` character
//!   inside `"..."` will confuse the brace counter. Documented limitation;
//!   produces a false negative on rare inputs.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;

use crate::findings::Match;

/// One `#[tauri::command]` function and its body bounds.
///
/// All offsets are byte offsets into the source string passed to
/// [`extract_tauri_commands`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TauriCommand {
    /// Function name as written.
    pub fn_name: String,
    /// Parameter identifier names (post-`mut` stripping, no types).
    pub params: Vec<String>,
    /// Body covering the matching `{ ... }` block.
    pub body: FunctionBody,
}

/// Byte and line offsets of one function body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionBody {
    /// Byte offset of the opening `{`.
    pub start: usize,
    /// Byte offset of the matching `}` (inclusive).
    pub end: usize,
    /// 1-indexed line of the function declaration (for finding location).
    pub fn_line: u32,
}

/// Walk `source` and return every `#[tauri::command]` annotated function
/// alongside its parameter list and matching brace-bounded body.
///
/// Skips functions where brace matching fails (e.g., body lives in a macro
/// expansion we can't see); those simply don't get traced rather than
/// producing a parse error.
#[must_use]
pub fn extract_tauri_commands(source: &str) -> Vec<TauriCommand> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(off) = source[pos..].find("#[tauri::command") {
        let attr_start = pos + off;
        // Move past the attribute closing bracket to find the `fn` keyword.
        let after_attr = if let Some(rel) = find_fn_keyword(&source[attr_start..]) {
            attr_start + rel
        } else {
            pos = attr_start + 1;
            continue;
        };
        let Some(parsed) = parse_fn_signature(&source[after_attr..]) else {
            pos = after_attr + 1;
            continue;
        };
        let body_open = after_attr + parsed.body_open_offset;
        let Some(body_close) = match_brace(source, body_open) else {
            pos = body_open + 1;
            continue;
        };
        let fn_line = u32::try_from(source[..after_attr].lines().count())
            .unwrap_or(1)
            .max(1);
        out.push(TauriCommand {
            fn_name: parsed.fn_name,
            params: parsed.params,
            body: FunctionBody {
                start: body_open,
                end: body_close,
                fn_line,
            },
        });
        pos = body_close + 1;
    }
    out
}

/// For each Tauri command function, scan the body for the listed sink regexes.
/// Emit one [`Match`] per (command, sink) pair where any tainted identifier
/// appears inside the sink's argument expression.
///
/// # Panics
///
/// Cannot panic in practice. The `unwrap()` calls dereference capture group 0
/// of a successful regex match, which always exists when `captures_iter`
/// yields a value.
#[must_use]
pub fn trace_tauri_sinks(
    source: &str,
    commands: &[TauriCommand],
    sinks: &[SinkPattern],
) -> Vec<Match> {
    let mut out = Vec::new();
    for cmd in commands {
        let body = &source[cmd.body.start..=cmd.body.end];
        let tainted = build_tainted_set(body, &cmd.params);

        for sink in sinks {
            for sink_match in sink.regex.captures_iter(body) {
                // A sink regex may use multiple alternations, each with its
                // own capture group for the arg expression. Walk groups
                // 1..N and use the first non-empty match.
                let args_text = (1..sink_match.len())
                    .find_map(|i| sink_match.get(i).map(|m| m.as_str()))
                    .unwrap_or("");
                if args_text.is_empty()
                    || !tainted.iter().any(|name| word_contained(args_text, name))
                {
                    continue;
                }
                let abs_match_start = cmd.body.start + sink_match.get(0).unwrap().start();
                if is_in_line_comment(source, abs_match_start) {
                    continue;
                }
                let line = line_of_offset(source, abs_match_start);
                out.push(Match {
                    rule_id: sink.rule_id.clone(),
                    line,
                    column: 1,
                    snippet: clip(sink_match.get(0).unwrap().as_str(), 200),
                });
            }
        }
    }
    out
}

/// Detect `unsafe { ... }` blocks inside Tauri command bodies and emit
/// [`Match`]es for the `tauri.unsafe_in_command` rule.
#[must_use]
pub fn trace_unsafe_in_commands(source: &str, commands: &[TauriCommand]) -> Vec<Match> {
    let mut out = Vec::new();
    let re = unsafe_block_re();
    for cmd in commands {
        let body = &source[cmd.body.start..=cmd.body.end];
        for m in re.find_iter(body) {
            let abs = cmd.body.start + m.start();
            if is_in_line_comment(source, abs) {
                continue;
            }
            out.push(Match {
                rule_id: "tauri.unsafe_in_command".into(),
                line: line_of_offset(source, abs),
                column: 1,
                snippet: clip(m.as_str(), 80),
            });
        }
    }
    out
}

/// One sink to watch for: a rule id and a regex that captures the call's
/// argument expression in its first capture group.
#[derive(Debug, Clone)]
pub struct SinkPattern {
    /// Rule id this sink fires (e.g. `tauri.command_injection`).
    pub rule_id: String,
    /// Compiled regex. Capture group 1 must be the argument expression.
    pub regex: Regex,
}

/// Default sink patterns Sentinel ships with.
///
/// # Errors
///
/// Returns an error only if a built-in regex fails to compile, which would
/// be a programming bug (the patterns are constants).
pub fn default_sink_patterns() -> anyhow::Result<Vec<SinkPattern>> {
    Ok(vec![
        SinkPattern {
            rule_id: "tauri.command_injection".into(),
            regex: Regex::new(r"(?:std::process::)?Command::new\s*\(([^;{}]+?)\)")?,
        },
        SinkPattern {
            rule_id: "tauri.path_traversal".into(),
            regex: Regex::new(
                r"(?:tauri::)?path::resolve_path\s*\([^,]*,\s*([^;{}]+?)\)|std::fs::(?:read_to_string|read|write|File::open|File::create)\s*\(([^;{}]+?)\)",
            )?,
        },
    ])
}

fn build_tainted_set(body: &str, params: &[String]) -> HashSet<String> {
    let mut set: HashSet<String> = params.iter().cloned().collect();
    // Find `let X = ...arg...;` and add X to the tainted set when the right
    // side mentions any already-tainted name.
    let re = let_binding_re();
    // Iterate to a fixed point so `let a = arg; let b = a;` adds both.
    loop {
        let before = set.len();
        for caps in re.captures_iter(body) {
            let Some(name) = caps.get(1) else { continue };
            let Some(rhs) = caps.get(2) else { continue };
            let name_str = name.as_str().to_string();
            if set.contains(&name_str) {
                continue;
            }
            if set.iter().any(|t| word_contained(rhs.as_str(), t)) {
                set.insert(name_str);
            }
        }
        if set.len() == before {
            break;
        }
    }
    set
}

fn let_binding_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // let [mut] NAME [: TYPE] = EXPR ;
        Regex::new(r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=;]+)?=\s*([^;]+);")
            .expect("let_binding_re")
    })
}

fn unsafe_block_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bunsafe\s*\{").expect("unsafe_block_re"))
}

/// True when `text` contains `needle` as a complete word (Rust-identifier-ish).
fn word_contained(text: &str, needle: &str) -> bool {
    let bytes = text.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() {
        return false;
    }
    let mut i = 0;
    while i + n.len() <= bytes.len() {
        if &bytes[i..i + n.len()] == n {
            let before_ok = i == 0 || !is_word_byte(bytes[i - 1]);
            let after = i + n.len();
            let after_ok = after == bytes.len() || !is_word_byte(bytes[after]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn find_fn_keyword(s: &str) -> Option<usize> {
    // Skip the attribute (e.g. `#[tauri::command(rename_all = "snake_case")]`)
    // by consuming until the closing `]`, then scanning forward to `fn`.
    let close = s.find(']')?;
    let after = &s[close + 1..];
    let fn_idx = after.find("fn ")?;
    Some(close + 1 + fn_idx)
}

#[derive(Debug)]
struct ParsedFn {
    fn_name: String,
    params: Vec<String>,
    body_open_offset: usize,
}

fn parse_fn_signature(s: &str) -> Option<ParsedFn> {
    // s starts with "fn NAME(params) -> ... { ... }"
    //
    // Offset math, indexed against the input `s`:
    //   skip          bytes consumed by "fn" + leading whitespace
    //   name_end      offset in after_fn where the function name ends
    //   paren_open    offset in after_name (== &after_fn[name_end..]) of `(`
    //   paren_close   matching `)` offset in after_name
    //   brace_off     offset in &after_name[paren_close+1..] of `{`
    //
    // body_open_offset = skip + name_end + paren_close + 1 + brace_off
    let after_fn = s.strip_prefix("fn")?.trim_start();
    let skip = s.len().saturating_sub(after_fn.len());

    let name_end = after_fn
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(after_fn.len());
    let fn_name = after_fn[..name_end].to_string();
    if fn_name.is_empty() {
        return None;
    }

    let after_name = &after_fn[name_end..];
    let paren_open = after_name.find('(')?;
    let paren_close = match_paren(after_name, paren_open)?;
    let params_text = &after_name[paren_open + 1..paren_close];
    let params = parse_params(params_text);

    let after_paren = &after_name[paren_close + 1..];
    let brace_off_in_after = after_paren.find('{')?;

    let body_open_offset = skip + name_end + paren_close + 1 + brace_off_in_after;

    Some(ParsedFn {
        fn_name,
        params,
        body_open_offset,
    })
}

fn parse_params(text: &str) -> Vec<String> {
    // Naive: split on commas at depth 0, take the part before `:`, strip `mut`.
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for c in text.chars() {
        match c {
            '<' | '(' | '[' => {
                depth += 1;
                current.push(c);
            }
            '>' | ')' | ']' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                push_param(&current, &mut out);
                current.clear();
            }
            _ => current.push(c),
        }
    }
    push_param(&current, &mut out);
    out
}

fn push_param(raw: &str, out: &mut Vec<String>) {
    let raw = raw.trim();
    if raw.is_empty() {
        return;
    }
    // Skip `self` / `&self` / `&mut self` — these aren't IPC-controlled inputs.
    if raw == "self" || raw == "&self" || raw == "&mut self" || raw.starts_with("self:") {
        return;
    }
    let before_colon = raw.split(':').next().unwrap_or("").trim();
    let stripped = before_colon
        .strip_prefix("mut ")
        .unwrap_or(before_colon)
        .trim();
    if stripped.is_empty() {
        return;
    }
    if !stripped
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return;
    }
    out.push(stripped.to_string());
}

fn match_brace(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open).copied() != Some(b'{') {
        return None;
    }
    let mut depth: i32 = 0;
    let mut i = open;
    let mut in_string: Option<u8> = None; // tracks `"` or `'`
    let mut in_block_comment = false;
    let mut in_line_comment = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_line_comment {
            if b == b'\n' {
                in_line_comment = false;
            }
            i += 1;
            continue;
        }
        if in_block_comment {
            if b == b'*' && bytes.get(i + 1).copied() == Some(b'/') {
                in_block_comment = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if let Some(q) = in_string {
            // Skip escape pairs.
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                in_string = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'/' if bytes.get(i + 1).copied() == Some(b'/') => {
                in_line_comment = true;
                i += 2;
            }
            b'/' if bytes.get(i + 1).copied() == Some(b'*') => {
                in_block_comment = true;
                i += 2;
            }
            b'"' | b'\'' => {
                in_string = Some(b);
                i += 1;
            }
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn match_paren(s: &str, open: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.get(open).copied() != Some(b'(') {
        return None;
    }
    let mut depth: i32 = 0;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn line_of_offset(source: &str, off: usize) -> u32 {
    let safe = off.min(source.len());
    let n = source[..safe].matches('\n').count() + 1;
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// True when `offset` falls inside a `//` line comment on its own line.
///
/// Cheap heuristic: scan back to the start of the line; if `//` appears
/// before `offset` on that line and isn't preceded by an opening string
/// quote, treat the offset as commented out. Block comments (`/* ... */`)
/// across multiple lines are not handled here — a Phase 2 tree-sitter pass
/// catches those.
#[must_use]
pub fn is_in_line_comment(source: &str, offset: usize) -> bool {
    let line_start = source[..offset].rfind('\n').map_or(0, |p| p + 1);
    let prefix = &source[line_start..offset];
    let Some(comment_pos) = prefix.find("//") else {
        return false;
    };
    let before_comment = &prefix[..comment_pos];
    let dquotes = before_comment.matches('"').count();
    dquotes.is_multiple_of(2)
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

    fn cmd_with_body(name: &str, params: &[&str], body: &str) -> String {
        format!(
            "#[tauri::command]\nfn {name}({}) {{\n{body}\n}}\n",
            params
                .iter()
                .map(|p| format!("{p}: String"))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }

    #[test]
    fn extracts_simple_tauri_command() {
        let src = cmd_with_body("run", &["input"], "    let _ = input;");
        let cmds = extract_tauri_commands(&src);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].fn_name, "run");
        assert_eq!(cmds[0].params, vec!["input".to_string()]);
    }

    #[test]
    fn extracts_multiple_commands() {
        let src = format!(
            "{}\n{}",
            cmd_with_body("a", &["x"], "let _ = x;"),
            cmd_with_body("b", &["y", "z"], "let _ = y; let _ = z;"),
        );
        let cmds = extract_tauri_commands(&src);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[1].params, vec!["y".to_string(), "z".to_string()]);
    }

    #[test]
    fn ignores_self_parameters() {
        let src = "#[tauri::command]\nimpl Foo { fn x(&self, arg: String) { } }\n";
        let cmds = extract_tauri_commands(src);
        // The function does parse, but `self` is excluded from params.
        if !cmds.is_empty() {
            assert!(!cmds[0].params.iter().any(|p| p == "self"));
        }
    }

    #[test]
    fn match_brace_handles_strings_with_braces() {
        let src = r#"fn x() { let s = "}"; let t = "{ also }"; }"#;
        let open = src.find('{').unwrap();
        let close = match_brace(src, open).unwrap();
        assert_eq!(&src[close..=close], "}");
        // close should be the LAST }, not one inside the string literal
        assert_eq!(close, src.rfind('}').unwrap());
    }

    #[test]
    fn match_brace_handles_line_comments_with_braces() {
        let src = "fn x() { // }\n let y = 1; }";
        let open = src.find('{').unwrap();
        let close = match_brace(src, open).unwrap();
        assert_eq!(close, src.rfind('}').unwrap());
    }

    #[test]
    fn dataflow_flags_command_injection_from_arg() {
        let src = cmd_with_body(
            "run_cmd",
            &["input"],
            "    let _ = std::process::Command::new(&input).spawn();",
        );
        let cmds = extract_tauri_commands(&src);
        let sinks = default_sink_patterns().unwrap();
        let matches = trace_tauri_sinks(&src, &cmds, &sinks);
        assert!(matches
            .iter()
            .any(|m| m.rule_id == "tauri.command_injection"));
    }

    #[test]
    fn dataflow_flags_command_injection_via_local_rename() {
        let src = cmd_with_body(
            "run_cmd",
            &["input"],
            "    let cmd = input;\n    Command::new(&cmd);",
        );
        let cmds = extract_tauri_commands(&src);
        let sinks = default_sink_patterns().unwrap();
        let matches = trace_tauri_sinks(&src, &cmds, &sinks);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_id == "tauri.command_injection"),
            "expected command_injection match, got {matches:?}"
        );
    }

    #[test]
    fn dataflow_flags_command_injection_via_field_access() {
        let src = cmd_with_body(
            "run_cmd",
            &["payload"],
            "    Command::new(&payload.binary).spawn();",
        );
        let cmds = extract_tauri_commands(&src);
        let sinks = default_sink_patterns().unwrap();
        let matches = trace_tauri_sinks(&src, &cmds, &sinks);
        assert!(matches
            .iter()
            .any(|m| m.rule_id == "tauri.command_injection"));
    }

    #[test]
    fn dataflow_does_not_flag_safe_command() {
        let src = cmd_with_body(
            "run_cmd",
            &["input"],
            "    Command::new(\"/usr/bin/ls\").arg(input).spawn();",
        );
        let cmds = extract_tauri_commands(&src);
        let sinks = default_sink_patterns().unwrap();
        let matches = trace_tauri_sinks(&src, &cmds, &sinks);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_id == "tauri.command_injection"),
            "literal binary should not be flagged"
        );
    }

    #[test]
    fn dataflow_skips_when_arg_only_appears_in_other_function() {
        let src = format!(
            "{}\n{}",
            cmd_with_body("a", &["arg"], "    let _ = arg;"),
            "fn helper() { Command::new(\"x\"); }",
        );
        let cmds = extract_tauri_commands(&src);
        let sinks = default_sink_patterns().unwrap();
        let matches = trace_tauri_sinks(&src, &cmds, &sinks);
        assert!(matches.is_empty(), "helper fn body should not be inspected");
    }

    #[test]
    fn unsafe_in_command_detected() {
        let src = cmd_with_body("x", &["arg"], "    let _ = arg;\n    unsafe { let _ = 1; }");
        let cmds = extract_tauri_commands(&src);
        let matches = trace_unsafe_in_commands(&src, &cmds);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "tauri.unsafe_in_command");
    }

    #[test]
    fn unsafe_outside_command_not_flagged() {
        let src = "fn helper() { unsafe { let _ = 1; } }\n";
        let cmds = extract_tauri_commands(src);
        let matches = trace_unsafe_in_commands(src, &cmds);
        assert!(matches.is_empty());
    }

    #[test]
    fn dataflow_tracks_let_chain() {
        let src = cmd_with_body(
            "x",
            &["arg"],
            "    let a = arg;\n    let b = a;\n    Command::new(&b).spawn();",
        );
        let cmds = extract_tauri_commands(&src);
        let sinks = default_sink_patterns().unwrap();
        let matches = trace_tauri_sinks(&src, &cmds, &sinks);
        assert!(matches
            .iter()
            .any(|m| m.rule_id == "tauri.command_injection"));
    }

    #[test]
    fn line_of_offset_matches_actual_lines() {
        let src = "line1\nline2\nline3";
        assert_eq!(line_of_offset(src, 0), 1);
        assert_eq!(line_of_offset(src, 6), 2);
        assert_eq!(line_of_offset(src, 12), 3);
    }
}
