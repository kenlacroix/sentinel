//! Map raw pattern / dataflow [`Match`]es into `sentinel_core::Finding`s,
//! attach the right metadata from the originating [`Pattern`], and dedup.

use sentinel_core::{Finding, Location, Tool};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::patterns::Pattern;

/// One raw match: produced by the regex scanner or the dataflow tracer
/// before any [`Pattern`] metadata has been attached.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Match {
    /// Rule id this match belongs to (e.g. `tauri.command_injection`).
    pub rule_id: String,
    /// 1-indexed line number in the source file.
    pub line: u32,
    /// 1-indexed column number; defaults to 1 when not known precisely.
    pub column: u32,
    /// Short snippet of the matching source for the report.
    pub snippet: String,
}

/// Convert raw matches into `Finding`s, joining each with its [`Pattern`]
/// metadata. Findings are sorted by severity (highest first) then by id.
///
/// `relative_path` should be relative to the project root so the report's
/// `Location.file` field is portable across machines.
#[must_use]
pub fn matches_to_findings(
    matches: &[Match],
    relative_path: &str,
    patterns: &[Pattern],
) -> Vec<Finding> {
    let by_id: BTreeMap<&str, &Pattern> = patterns.iter().map(|p| (p.id.as_str(), p)).collect();
    let mut out = Vec::with_capacity(matches.len());
    for m in matches {
        let Some(pattern) = by_id.get(m.rule_id.as_str()) else {
            tracing::warn!(
                rule_id = %m.rule_id,
                "match references unknown rule id; skipping"
            );
            continue;
        };
        out.push(Finding {
            id: format!("analyzer.{}.{}:{}", m.rule_id, relative_path, m.line),
            title: format!("{} ({}:{})", pattern.title, relative_path, m.line),
            description: build_description(pattern, m),
            severity: pattern.severity,
            tool: Tool::Analyzer,
            component: relative_path.to_string(),
            suggestion: pattern.suggestion.clone(),
            location: Some(Location::new(relative_path.to_string(), Some(m.line))),
            references: pattern.references.clone(),
        });
    }
    out
}

fn build_description(pattern: &Pattern, m: &Match) -> String {
    let mut s = pattern.description.clone();
    if !m.snippet.is_empty() {
        s.push_str("\n\nMatch: ");
        s.push_str(&m.snippet);
    }
    s
}

/// Deduplicate findings by id (file + line + rule), keeping the first match.
/// Sort by severity (descending) then id (ascending) for stable report ordering.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::builtin_patterns;
    use sentinel_core::Severity;

    #[test]
    fn match_becomes_finding_with_pattern_metadata() {
        let m = Match {
            rule_id: "webview.eval".to_string(),
            line: 42,
            column: 1,
            snippet: "eval(input)".to_string(),
        };
        let findings = matches_to_findings(&[m], "src/App.tsx", &builtin_patterns());
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.tool, Tool::Analyzer);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.component, "src/App.tsx");
        assert_eq!(f.location.as_ref().unwrap().file, "src/App.tsx");
        assert_eq!(f.location.as_ref().unwrap().line, Some(42));
        assert!(f.description.contains("eval"));
        assert!(f.description.contains("Match: eval(input)"));
    }

    #[test]
    fn unknown_rule_id_is_skipped_with_warning() {
        let m = Match {
            rule_id: "no.such.rule".to_string(),
            line: 1,
            column: 1,
            snippet: "x".to_string(),
        };
        let findings = matches_to_findings(&[m], "x.rs", &builtin_patterns());
        assert!(findings.is_empty());
    }

    #[test]
    fn dedup_removes_duplicate_ids() {
        let pattern = builtin_patterns()
            .into_iter()
            .find(|p| p.id == "webview.eval")
            .unwrap();
        let m = Match {
            rule_id: pattern.id.clone(),
            line: 10,
            column: 1,
            snippet: "eval(x)".into(),
        };
        let mut findings = matches_to_findings(
            std::slice::from_ref(&m),
            "a.tsx",
            std::slice::from_ref(&pattern),
        );
        findings.extend(matches_to_findings(&[m], "a.tsx", &[pattern]));
        let deduped = dedup_findings(findings);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn dedup_keeps_distinct_lines() {
        let pattern = builtin_patterns()
            .into_iter()
            .find(|p| p.id == "webview.eval")
            .unwrap();
        let m1 = Match {
            rule_id: pattern.id.clone(),
            line: 10,
            column: 1,
            snippet: "x".into(),
        };
        let m2 = Match {
            rule_id: pattern.id.clone(),
            line: 20,
            column: 1,
            snippet: "y".into(),
        };
        let findings = matches_to_findings(&[m1, m2], "a.tsx", &[pattern]);
        let deduped = dedup_findings(findings);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn dedup_sorts_critical_before_high() {
        let mut patterns = builtin_patterns();
        // Two patterns of different severity; build two matches.
        let high_p = patterns
            .iter()
            .find(|p| p.severity == Severity::High)
            .unwrap()
            .clone();
        let crit_p = patterns
            .iter()
            .find(|p| p.severity == Severity::Critical)
            .unwrap()
            .clone();
        patterns.clear();
        patterns.push(high_p.clone());
        patterns.push(crit_p.clone());

        let m_high = Match {
            rule_id: high_p.id,
            line: 10,
            column: 1,
            snippet: "h".into(),
        };
        let m_crit = Match {
            rule_id: crit_p.id,
            line: 20,
            column: 1,
            snippet: "c".into(),
        };
        let mut findings = matches_to_findings(&[m_high], "a.rs", &patterns);
        findings.extend(matches_to_findings(&[m_crit], "a.rs", &patterns));
        let sorted = dedup_findings(findings);
        assert_eq!(sorted[0].severity, Severity::Critical);
        assert_eq!(sorted[1].severity, Severity::High);
    }
}
