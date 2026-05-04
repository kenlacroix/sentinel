//! Suppression handling: inline `// sentinel:ignore` comments and
//! `.sentinelignore` glob files.
//!
//! Two layers cooperate:
//!
//! 1. **`.sentinelignore`** at project root — gitignore-style globs that
//!    exclude entire paths from scanning. Honored by [`crate::scanner`]
//!    before any matching happens.
//! 2. **Inline `// sentinel:ignore` comments** — fine-grained suppression
//!    on the line where a finding would otherwise fire. Supports per-rule
//!    targeting so a noisy rule can be silenced without disabling other
//!    detections on that line.
//!
//! Inline forms accepted:
//!
//! ```text
//! // sentinel:ignore                       — silences ALL rules on this line
//! // sentinel:ignore-next-line             — silences ALL rules on the next line
//! // sentinel:ignore-rule:webview.eval     — silences only this rule on the line
//! // sentinel:ignore-rule:webview.eval,crypto.weak_hash  — multiple rules
//! ```
//!
//! Block-comment equivalents (`/* sentinel:ignore */`) are recognised too.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Gitignore-style glob, parsed once and reused per scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SentinelIgnore {
    /// Patterns parsed from `.sentinelignore`, in source order.
    pub patterns: Vec<String>,
}

impl SentinelIgnore {
    /// Read `<root>/.sentinelignore` if it exists. Missing file → empty
    /// ignore set, not an error — this is the common case.
    #[must_use]
    pub fn load(project_root: &std::path::Path) -> Self {
        let path = project_root.join(".sentinelignore");
        let raw = std::fs::read_to_string(&path).unwrap_or_default();
        let patterns = raw
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect();
        Self { patterns }
    }

    /// Return true if the relative path (forward slashes) matches any pattern.
    #[must_use]
    pub fn is_ignored(&self, rel_path: &str) -> bool {
        self.patterns.iter().any(|p| matches_glob(p, rel_path))
    }
}

/// Per-line, per-rule suppression decisions for one source file.
#[derive(Debug, Clone, Default)]
pub struct SuppressionMap {
    /// `line_number → rules suppressed on that line`.
    /// `None` means "all rules suppressed".
    rules_per_line: HashMap<u32, Suppression>,
}

#[derive(Debug, Clone)]
enum Suppression {
    /// Suppress every rule on this line.
    All,
    /// Suppress only the listed rule ids.
    Rules(Vec<String>),
}

impl SuppressionMap {
    /// Returns true if `rule_id` should be suppressed on `line` (1-indexed).
    #[must_use]
    pub fn is_suppressed(&self, line: u32, rule_id: &str) -> bool {
        match self.rules_per_line.get(&line) {
            Some(Suppression::All) => true,
            Some(Suppression::Rules(rules)) => rules.iter().any(|r| r == rule_id),
            None => false,
        }
    }

    /// Number of suppression directives parsed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules_per_line.len()
    }

    /// `true` if no directives were parsed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules_per_line.is_empty()
    }
}

/// Scan source content for `// sentinel:ignore[...]` directives and build
/// a [`SuppressionMap`] keyed by 1-indexed line number.
#[must_use]
pub fn parse_inline_ignores(source: &str) -> SuppressionMap {
    let mut map = SuppressionMap::default();
    for (idx, line) in source.lines().enumerate() {
        // 1-indexed
        let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        let Some(directive) = extract_directive(line) else {
            continue;
        };
        match directive {
            Directive::AllSame => {
                map.rules_per_line.insert(lineno, Suppression::All);
            }
            Directive::AllNext => {
                map.rules_per_line.insert(lineno + 1, Suppression::All);
            }
            Directive::RulesSame(rules) => {
                map.rules_per_line.insert(lineno, Suppression::Rules(rules));
            }
            Directive::RulesNext(rules) => {
                map.rules_per_line
                    .insert(lineno + 1, Suppression::Rules(rules));
            }
        }
    }
    map
}

/// Suppression scope a single `sentinel:ignore` comment expresses.
#[derive(Debug)]
enum Directive {
    /// Silence every rule on the same line as the directive.
    AllSame,
    /// Silence every rule on the line after the directive.
    AllNext,
    /// Silence the listed rule ids on the same line.
    RulesSame(Vec<String>),
    /// Silence the listed rule ids on the next line.
    RulesNext(Vec<String>),
}

fn extract_directive(line: &str) -> Option<Directive> {
    // Find the first occurrence of `sentinel:ignore` in a comment.
    let comment_start = line.find("//").or_else(|| line.find("/*"))?;
    let after_comment = &line[comment_start..];
    let rest = after_comment.split_once("sentinel:ignore")?.1;

    // Now `rest` is the chunk after `sentinel:ignore`. Check the modifier.
    let trimmed = rest.trim_start();

    if let Some(after) = trimmed.strip_prefix("-next-line") {
        let rules = parse_rules_clause(after);
        return Some(if rules.is_empty() {
            Directive::AllNext
        } else {
            Directive::RulesNext(rules)
        });
    }
    if let Some(after) = trimmed.strip_prefix("-rule:") {
        let rules = parse_rule_list(after);
        return Some(Directive::RulesSame(rules));
    }
    Some(Directive::AllSame)
}

fn parse_rules_clause(after: &str) -> Vec<String> {
    let trimmed = after.trim_start();
    if let Some(rest) = trimmed.strip_prefix(":") {
        // Form: -next-line:rule1,rule2
        return parse_rule_list(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("-rule:") {
        // Form: -next-line-rule:rule1
        return parse_rule_list(rest);
    }
    vec![]
}

fn parse_rule_list(after: &str) -> Vec<String> {
    after
        .split([',', ' ', '\t', ')', '*', '/'])
        .map(str::trim)
        .filter(|s| !s.is_empty() && is_rule_id_char(s))
        .map(str::to_string)
        .collect()
}

fn is_rule_id_char(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// Minimal gitignore-style glob matcher.
///
/// Supports:
/// - `*` matches any chars except `/`
/// - `**` matches any chars including `/`
/// - `**/` at a path segment boundary matches zero or more directory components
/// - Trailing `/` matches a directory prefix (anything beneath the path)
/// - A pattern containing no `/` matches the path *basename* at any depth
///   (gitignore-style "unanchored" matching)
fn matches_glob(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('/') {
        return path == prefix
            || path.starts_with(&format!("{prefix}/"))
            || path.split('/').any(|seg| seg == prefix);
    }

    let has_slash = pattern.contains('/');
    let regex_src = build_glob_regex(pattern);
    let final_regex = if has_slash {
        format!("^{regex_src}$")
    } else {
        // Unanchored: match any path component or the file's basename.
        format!("(?:^|/){regex_src}$")
    };
    regex::Regex::new(&final_regex).is_ok_and(|re| re.is_match(path))
}

fn build_glob_regex(pattern: &str) -> String {
    let mut out = String::new();
    let mut chars = pattern.chars().peekable();
    let mut at_segment_start = true;
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next();
                    // `**/` at a path-segment boundary matches zero+ dirs
                    if at_segment_start && chars.peek() == Some(&'/') {
                        chars.next();
                        out.push_str("(?:.*/)?");
                        at_segment_start = true;
                        continue;
                    }
                    out.push_str(".*");
                } else {
                    out.push_str("[^/]*");
                }
            }
            '?' => out.push('.'),
            '/' => {
                out.push('/');
                at_segment_start = true;
                continue;
            }
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
        at_segment_start = false;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_source_yields_empty_map() {
        let m = parse_inline_ignores("");
        assert!(m.is_empty());
    }

    #[test]
    fn same_line_all_directive_suppresses_any_rule() {
        let src = r"let x = eval(input); // sentinel:ignore
let y = nothing();";
        let m = parse_inline_ignores(src);
        assert!(m.is_suppressed(1, "webview.eval"));
        assert!(m.is_suppressed(1, "any.other"));
        assert!(!m.is_suppressed(2, "webview.eval"));
    }

    #[test]
    fn next_line_directive_targets_following_line() {
        let src = r"// sentinel:ignore-next-line
eval(userInput)
eval(other)";
        let m = parse_inline_ignores(src);
        assert!(m.is_suppressed(2, "webview.eval"));
        assert!(!m.is_suppressed(3, "webview.eval"));
    }

    #[test]
    fn rule_specific_directive_suppresses_only_listed_rules() {
        let src = "let x = eval(y); // sentinel:ignore-rule:webview.eval\n";
        let m = parse_inline_ignores(src);
        assert!(m.is_suppressed(1, "webview.eval"));
        assert!(!m.is_suppressed(1, "crypto.weak_hash"));
    }

    #[test]
    fn rule_specific_directive_with_multiple_rules() {
        let src = "x // sentinel:ignore-rule:a.b,c.d\n";
        let m = parse_inline_ignores(src);
        assert!(m.is_suppressed(1, "a.b"));
        assert!(m.is_suppressed(1, "c.d"));
        assert!(!m.is_suppressed(1, "e.f"));
    }

    #[test]
    fn block_comment_form_is_recognised() {
        let src = "Md5::new() /* sentinel:ignore */\n";
        let m = parse_inline_ignores(src);
        assert!(m.is_suppressed(1, "crypto.weak_hash"));
    }

    #[test]
    fn unrelated_lines_have_no_suppression() {
        let src = "let x = 1;\nlet y = 2;\n";
        let m = parse_inline_ignores(src);
        assert!(!m.is_suppressed(1, "anything"));
        assert!(!m.is_suppressed(2, "anything"));
    }

    #[test]
    fn sentinel_ignore_loads_patterns_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(".sentinelignore"),
            "# comment line\nsrc/legacy/\n*.bak\n   \n",
        )
        .unwrap();
        let ig = SentinelIgnore::load(tmp.path());
        assert_eq!(ig.patterns.len(), 2);
        assert_eq!(ig.patterns[0], "src/legacy/");
        assert_eq!(ig.patterns[1], "*.bak");
    }

    #[test]
    fn sentinel_ignore_missing_file_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let ig = SentinelIgnore::load(tmp.path());
        assert!(ig.patterns.is_empty());
    }

    #[test]
    fn glob_matches_directory_prefix() {
        assert!(matches_glob("src/legacy/", "src/legacy/foo.rs"));
        assert!(matches_glob("src/legacy/", "src/legacy"));
        assert!(!matches_glob("src/legacy/", "src/main.rs"));
    }

    #[test]
    fn glob_matches_extension_pattern() {
        assert!(matches_glob("*.bak", "stale.bak"));
        assert!(matches_glob("*.bak", "src/foo.bak"));
        assert!(!matches_glob("*.bak", "stale.rs"));
    }

    #[test]
    fn glob_matches_double_star_across_dirs() {
        assert!(matches_glob("**/*.tsx", "src/components/Foo.tsx"));
        assert!(matches_glob("**/*.tsx", "Foo.tsx"));
        assert!(!matches_glob("**/*.tsx", "Foo.ts"));
    }

    #[test]
    fn sentinel_ignore_combines_patterns() {
        let ig = SentinelIgnore {
            patterns: vec!["target/".into(), "*.bak".into(), "vendor/".into()],
        };
        assert!(ig.is_ignored("target/x.rs"));
        assert!(ig.is_ignored("vendor/lib.rs"));
        assert!(ig.is_ignored("a.bak"));
        assert!(!ig.is_ignored("src/main.rs"));
    }
}
