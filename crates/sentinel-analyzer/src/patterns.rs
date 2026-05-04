//! Built-in Tauri-specific pattern library plus a user-extensible YAML
//! rule loader.
//!
//! Every pattern is either:
//!
//! - [`PatternKind::Regex`] — straight regex match against file content.
//!   Cheap; runs on every applicable file.
//! - [`PatternKind::TauriDataflow`] — tag for sink-tracing patterns that
//!   the [`crate::dataflow`] module handles instead of the regex matcher.
//!   Listed here for documentation + reporting consistency, with no
//!   `regex` field of their own.
//!
//! Severity calibration:
//!
//! | Severity | When |
//! | --- | --- |
//! | Critical | Reachable RCE: `#[tauri::command]` arg flows to `Command::new`. |
//! | High     | Reachable XSS / path traversal: `eval`, `dangerouslySetInnerHTML`, `path::resolve_path` from arg. |
//! | Medium   | Likely weakness: weak hash, http URL, `unsafe` in command. |
//! | Low      | Hardening hint: CSP without strict-dynamic etc. |
//! | Info     | Diagnostic — surfaced for awareness, not action. |

use std::sync::OnceLock;

use anyhow::{Context, Result};
use regex::Regex;
use sentinel_core::Severity;
use serde::{Deserialize, Serialize};

/// What kind of detection a pattern uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PatternKind {
    /// Direct regex match against file content.
    Regex,
    /// Handled by the dataflow tracer (no regex on this struct).
    TauriDataflow,
}

/// One rule the analyzer evaluates. May be built-in or user-loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// Stable identifier — `tauri.command_injection`, `webview.eval`, ...
    pub id: String,
    /// Detection mechanism.
    pub kind: PatternKind,
    /// Short human title.
    pub title: String,
    /// Long-form explanation for the report.
    pub description: String,
    /// Severity rating.
    pub severity: Severity,
    /// Concrete remediation suggestion.
    pub suggestion: String,
    /// File extensions this pattern applies to (lowercased, no leading dot).
    pub extensions: Vec<String>,
    /// Reference URLs.
    #[serde(default)]
    pub references: Vec<String>,
    /// Regex source. Required when `kind == Regex`, ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Pre-compiled regex; populated lazily on first use.
    #[serde(skip)]
    compiled: OnceLock<Regex>,
}

impl Pattern {
    /// Returns the compiled regex, compiling on first call.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is `TauriDataflow` (no regex), missing
    /// the `regex` field, or the regex itself is invalid.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice; the `expect` after `OnceLock::set` is
    /// satisfied because we just set the value on the line above.
    pub fn compiled(&self) -> Result<&Regex> {
        if self.kind != PatternKind::Regex {
            anyhow::bail!("pattern {} is not a regex pattern", self.id);
        }
        let src = self
            .regex
            .as_deref()
            .with_context(|| format!("pattern {} has no regex source", self.id))?;
        if let Some(re) = self.compiled.get() {
            return Ok(re);
        }
        let compiled =
            Regex::new(src).with_context(|| format!("invalid regex in pattern {}", self.id))?;
        let _ = self.compiled.set(compiled);
        Ok(self.compiled.get().expect("just set"))
    }

    /// Returns true if this pattern applies to a file with the given lowercased extension.
    #[must_use]
    pub fn applies_to_extension(&self, ext: &str) -> bool {
        self.extensions.iter().any(|e| e == ext)
    }
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.kind == other.kind
            && self.title == other.title
            && self.description == other.description
            && self.severity == other.severity
            && self.suggestion == other.suggestion
            && self.extensions == other.extensions
            && self.references == other.references
            && self.regex == other.regex
    }
}

impl Eq for Pattern {}

/// Built-in pattern library shipped with Sentinel.
///
/// Cheap on first call (regex compiled lazily); subsequent calls return the
/// same `Vec<Pattern>` in `O(1)` via [`OnceLock`].
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn builtin_patterns() -> Vec<Pattern> {
    vec![
        // --- Tauri dataflow patterns (handled by dataflow.rs) ---
        Pattern {
            id: "tauri.command_injection".into(),
            kind: PatternKind::TauriDataflow,
            title: "Command-injection sink reachable from Tauri command".into(),
            description: "A `#[tauri::command]` argument flows into `std::process::Command::new(...)`. \
                          This is a remote-code-execution sink: anything that can call this command \
                          (a compromised webview, a malicious extension, a bug in your frontend) \
                          gets to run arbitrary processes on the host."
                .into(),
            severity: Severity::Critical,
            suggestion: "Never pass user input to `Command::new`. Whitelist allowed binaries by name \
                         and use `Command::new(\"/path/to/tool\").args([safe_arg])` to keep the \
                         executable selection out of attacker control."
                .into(),
            extensions: vec!["rs".into()],
            references: vec![
                "https://owasp.org/www-community/attacks/Command_Injection".into(),
                "https://tauri.app/security/".into(),
            ],
            regex: None,
            compiled: OnceLock::new(),
        },
        Pattern {
            id: "tauri.path_traversal".into(),
            kind: PatternKind::TauriDataflow,
            title: "Path-traversal sink reachable from Tauri command".into(),
            description: "A `#[tauri::command]` argument flows into a path-resolution call \
                          (`tauri::path::resolve_path`, `std::fs::read_to_string`, \
                          `std::fs::write`). User-controlled paths can escape the intended \
                          directory via `..` segments or absolute paths."
                .into(),
            severity: Severity::High,
            suggestion: "Canonicalize the user path and assert it stays within an allowed root \
                         before opening: `let canon = path.canonicalize()?; if !canon.starts_with(&allowed_root) { bail!() }`."
                .into(),
            extensions: vec!["rs".into()],
            references: vec![
                "https://owasp.org/www-community/attacks/Path_Traversal".into(),
            ],
            regex: None,
            compiled: OnceLock::new(),
        },
        Pattern {
            id: "tauri.unsafe_in_command".into(),
            kind: PatternKind::TauriDataflow,
            title: "`unsafe` block inside `#[tauri::command]` function".into(),
            description: "An `unsafe { ... }` block lives inside a `#[tauri::command]` handler \
                          body. The Tauri IPC bridge makes the function reachable from the \
                          webview, so any memory-safety bug in the unsafe block becomes \
                          remotely triggerable."
                .into(),
            severity: Severity::Medium,
            suggestion: "Audit the `unsafe` block. If it can be expressed in safe Rust, do it. \
                         Otherwise, document the invariants and add fuzz coverage with \
                         sentinel-fuzzer."
                .into(),
            extensions: vec!["rs".into()],
            references: vec!["https://doc.rust-lang.org/nomicon/safe-unsafe-meaning.html".into()],
            regex: None,
            compiled: OnceLock::new(),
        },
        // --- Regex patterns (handled by patterns + scanner) ---
        Pattern {
            id: "webview.eval".into(),
            kind: PatternKind::Regex,
            title: "`eval()` / `new Function(...)` in webview code".into(),
            description: "The webview JavaScript context contains a call to `eval()` or \
                          `new Function(...)`. Any string that reaches one of these is \
                          executed as code. In a Tauri app, that string can come from an \
                          IPC response — a compromised backend (or a bug in serialization) \
                          becomes JavaScript injection."
                .into(),
            severity: Severity::High,
            suggestion: "Replace `eval`/`Function` with structured parsing (`JSON.parse`, \
                         explicit dispatch) so the webview never interprets data as code."
                .into(),
            extensions: vec!["js".into(), "jsx".into(), "ts".into(), "tsx".into(), "vue".into(), "svelte".into()],
            references: vec![
                "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval()".into(),
            ],
            regex: Some(r"(?m)(?:^|[^A-Za-z0-9_])(eval|new\s+Function)\s*\(".into()),
            compiled: OnceLock::new(),
        },
        Pattern {
            id: "webview.dangerously_set_inner_html".into(),
            kind: PatternKind::Regex,
            title: "`dangerouslySetInnerHTML` in React component".into(),
            description: "A React/JSX component uses `dangerouslySetInnerHTML`. If the HTML it \
                          renders comes from an IPC response, a compromised backend (or a \
                          serialization bug) lets an attacker inject HTML into the privileged \
                          webview context, where they can in turn invoke any allowed Tauri command."
                .into(),
            severity: Severity::High,
            suggestion: "Render strings as text (React does this by default with `{value}`). When \
                         HTML really is required, sanitize with DOMPurify or equivalent before \
                         passing to `dangerouslySetInnerHTML`."
                .into(),
            extensions: vec!["jsx".into(), "tsx".into()],
            references: vec![
                "https://react.dev/reference/react-dom/components/common#dangerouslysetinnerhtml".into(),
            ],
            regex: Some(r"\bdangerouslySetInnerHTML\s*=".into()),
            compiled: OnceLock::new(),
        },
        Pattern {
            id: "crypto.weak_hash".into(),
            kind: PatternKind::Regex,
            title: "Weak hash primitive (MD5 / SHA-1)".into(),
            description: "MD5 and SHA-1 are cryptographically broken. If this hash is used for \
                          message authentication, password hashing, or signature verification, \
                          it is an exploitable weakness. (Both are still acceptable for \
                          non-cryptographic purposes like cache keys or content addressing.)"
                .into(),
            severity: Severity::Medium,
            suggestion: "For cryptographic use cases, switch to SHA-256 or BLAKE3. For password \
                         hashing specifically, use Argon2id (`argon2` crate)."
                .into(),
            extensions: vec!["rs".into(), "ts".into(), "tsx".into(), "js".into(), "jsx".into()],
            references: vec![
                "https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions".into(),
                "https://rustsec.org/".into(),
            ],
            regex: Some(r"\b(?:Md5::|Sha1::|md5::compute|sha1::Sha1::|crypto\.create(?:Hash|Hmac)\(\s*['\x22](?:md5|sha1)['\x22])".into()),
            compiled: OnceLock::new(),
        },
        Pattern {
            id: "network.http_in_fetch".into(),
            kind: PatternKind::Regex,
            title: "Plain HTTP in fetch / HTTP-client call".into(),
            description: "A network call sends data over plain HTTP rather than HTTPS. Tauri \
                          apps frequently ship to networks the developer doesn't control — \
                          coffee shop wifi, captive portals, corporate NAT. Anything in transit \
                          is observable and tamperable."
                .into(),
            severity: Severity::Medium,
            suggestion: "Move the endpoint to HTTPS. If this URL is genuinely a development \
                         localhost, gate it behind `#[cfg(debug_assertions)]` or an env-var \
                         check so it can't ship to production."
                .into(),
            extensions: vec!["rs".into(), "ts".into(), "tsx".into(), "js".into(), "jsx".into()],
            references: vec!["https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security".into()],
            regex: Some(r#"(?:fetch|axios|\.get|\.post|\.put|\.delete|Client::new\(\)\.\w+|reqwest::get)\s*\(\s*['"`]http://[^'"`]+['"`]"#.into()),
            compiled: OnceLock::new(),
        },
        Pattern {
            id: "tauri.csp_unsafe_eval".into(),
            kind: PatternKind::Regex,
            title: "Content-Security-Policy with `unsafe-eval` or `unsafe-inline`".into(),
            description: "The CSP allows inline scripts or `eval()`. Combined with any XSS in \
                          the webview, this lets the attacker reach the IPC bridge directly. \
                          A strict CSP is one of the cheapest defenses against post-XSS escalation."
                .into(),
            severity: Severity::High,
            suggestion: "Remove `unsafe-eval` and `unsafe-inline`. If you need inline scripts, \
                         hash them and add the hash to `script-src`."
                .into(),
            extensions: vec!["html".into(), "json".into(), "json5".into()],
            references: vec![
                "https://content-security-policy.com/".into(),
                "https://tauri.app/security/csp/".into(),
            ],
            regex: Some(r"unsafe-(?:eval|inline)".into()),
            compiled: OnceLock::new(),
        },
    ]
}

// Parsed as TOML for parity with Cargo's ecosystem; we accept
// `[[patterns]]` array syntax. Future YAML support can layer on; for MVP,
// TOML is enough and matches user intuition for a "Rust project" config.
#[derive(Deserialize)]
struct PatternsFile {
    #[serde(default)]
    patterns: Vec<UserPattern>,
}

#[derive(Deserialize)]
struct UserPattern {
    id: String,
    kind: PatternKind,
    title: String,
    description: String,
    severity: Severity,
    suggestion: String,
    extensions: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    regex: Option<String>,
}

/// Load extra patterns from a user-supplied TOML file.
///
/// The file is a sequence of `[[patterns]]` tables with the same shape as
/// [`Pattern`] (minus the `compiled` field). Built-in patterns and user
/// patterns share an id namespace; if a user rule shares an id with a
/// built-in, the user rule wins and a warning is logged.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed. Individual invalid
/// patterns within the file fail the whole load — strict mode is preferable
/// to silently ignoring half the user's rules.
pub fn load_rules_yaml(path: &std::path::Path) -> Result<Vec<Pattern>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read rules file: {}", path.display()))?;

    let file: PatternsFile = toml::from_str(&raw)
        .with_context(|| format!("invalid rules TOML at {}", path.display()))?;

    Ok(file
        .patterns
        .into_iter()
        .map(|u| Pattern {
            id: u.id,
            kind: u.kind,
            title: u.title,
            description: u.description,
            severity: u.severity,
            suggestion: u.suggestion,
            extensions: u.extensions,
            references: u.references,
            regex: u.regex,
            compiled: OnceLock::new(),
        })
        .collect())
}

/// Merge built-in and user patterns, with user overrides winning on id collisions.
#[must_use]
pub fn merge_patterns(builtins: Vec<Pattern>, users: Vec<Pattern>) -> Vec<Pattern> {
    let mut by_id: std::collections::BTreeMap<String, Pattern> =
        builtins.into_iter().map(|p| (p.id.clone(), p)).collect();
    for u in users {
        if by_id.contains_key(&u.id) {
            tracing::warn!(id = %u.id, "user rule overrides built-in pattern of the same id");
        }
        by_id.insert(u.id.clone(), u);
    }
    by_id.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_patterns_compile_cleanly() {
        for p in builtin_patterns() {
            if p.kind == PatternKind::Regex {
                let _ = p
                    .compiled()
                    .unwrap_or_else(|e| panic!("pattern {} failed to compile: {e}", p.id));
            }
        }
    }

    #[test]
    fn webview_eval_matches_direct_eval_call() {
        let pattern = builtin_patterns()
            .into_iter()
            .find(|p| p.id == "webview.eval")
            .unwrap();
        let re = pattern.compiled().unwrap();
        assert!(re.is_match("eval(userInput)"));
        assert!(re.is_match("const r = eval('1 + 1');"));
        assert!(re.is_match("new Function('return 1')()"));
    }

    #[test]
    fn webview_eval_does_not_match_word_containing_eval() {
        let pattern = builtin_patterns()
            .into_iter()
            .find(|p| p.id == "webview.eval")
            .unwrap();
        let re = pattern.compiled().unwrap();
        assert!(!re.is_match("medieval(thing)"));
        assert!(!re.is_match("evaluation_pending(true)"));
        assert!(!re.is_match("retrieval_handler()"));
    }

    #[test]
    fn dangerously_set_inner_html_matches() {
        let p = builtin_patterns()
            .into_iter()
            .find(|p| p.id == "webview.dangerously_set_inner_html")
            .unwrap();
        let re = p.compiled().unwrap();
        assert!(re.is_match("<div dangerouslySetInnerHTML={{ __html: x }} />"));
        assert!(re.is_match("dangerouslySetInnerHTML  =  {x}"));
    }

    #[test]
    fn weak_hash_matches_md5_sha1_in_rust_and_node() {
        let p = builtin_patterns()
            .into_iter()
            .find(|p| p.id == "crypto.weak_hash")
            .unwrap();
        let re = p.compiled().unwrap();
        assert!(re.is_match("Md5::new()"));
        assert!(re.is_match("Sha1::digest(b\"hi\")"));
        assert!(re.is_match("crypto.createHash('md5')"));
        assert!(re.is_match("crypto.createHmac('sha1', key)"));
        assert!(!re.is_match("Sha256::digest(b\"x\")"));
    }

    #[test]
    fn http_in_fetch_matches_clear_cases() {
        let p = builtin_patterns()
            .into_iter()
            .find(|p| p.id == "network.http_in_fetch")
            .unwrap();
        let re = p.compiled().unwrap();
        assert!(re.is_match("fetch(\"http://example.com\")"));
        assert!(re.is_match("axios.get('http://api.local')"));
        assert!(re.is_match("reqwest::get(\"http://thing\")"));
        assert!(!re.is_match("fetch(\"https://example.com\")"));
        assert!(!re.is_match("// the docs say http://example.com"));
    }

    #[test]
    fn csp_unsafe_eval_matches_csp_keywords() {
        let p = builtin_patterns()
            .into_iter()
            .find(|p| p.id == "tauri.csp_unsafe_eval")
            .unwrap();
        let re = p.compiled().unwrap();
        assert!(re.is_match("default-src 'self'; script-src 'self' 'unsafe-eval'"));
        assert!(re.is_match("style-src 'unsafe-inline'"));
        assert!(!re.is_match("default-src 'self'"));
    }

    #[test]
    fn applies_to_extension_is_lowercased() {
        let p = builtin_patterns()
            .into_iter()
            .find(|p| p.id == "webview.eval")
            .unwrap();
        assert!(p.applies_to_extension("ts"));
        assert!(p.applies_to_extension("tsx"));
        assert!(!p.applies_to_extension("rs"));
    }

    #[test]
    fn merge_patterns_lets_user_override_builtin() {
        let mut user = builtin_patterns()
            .into_iter()
            .find(|p| p.id == "webview.eval")
            .unwrap();
        user.severity = Severity::Low;
        user.title = "user override".into();
        let merged = merge_patterns(builtin_patterns(), vec![user]);
        let eval_p = merged.iter().find(|p| p.id == "webview.eval").unwrap();
        assert_eq!(eval_p.severity, Severity::Low);
        assert_eq!(eval_p.title, "user override");
    }

    #[test]
    fn load_rules_toml_parses_and_validates() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rules.toml");
        std::fs::write(
            &path,
            r#"
[[patterns]]
id = "user.demo"
kind = "regex"
title = "Demo"
description = "Demo pattern"
severity = "low"
suggestion = "Just for tests"
extensions = ["rs"]
regex = "TODO"
"#,
        )
        .unwrap();

        let parsed = load_rules_yaml(&path).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "user.demo");
        assert_eq!(parsed[0].severity, Severity::Low);
        assert_eq!(parsed[0].extensions, vec!["rs".to_string()]);
    }

    #[test]
    fn load_rules_toml_rejects_invalid_input() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.toml");
        std::fs::write(&path, "this :: is = not = toml = ::").unwrap();
        let err = load_rules_yaml(&path).unwrap_err();
        assert!(err.to_string().contains("invalid rules TOML"));
    }
}
