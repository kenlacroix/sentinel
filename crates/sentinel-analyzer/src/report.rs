//! Report serialization: JSON (matches the cartographer / fuzzer shape) and
//! self-contained HTML (no remote assets, embedded CSS, single file).

use anyhow::{Context, Result};
use sentinel_core::{Finding, Report, Severity};
use std::fmt::Write;

/// Serialize a [`Report`] to pretty-printed JSON.
///
/// # Errors
///
/// Returns an error only if the underlying `serde_json` serialization fails,
/// which would indicate a programming bug rather than user-input issue.
pub fn render_json(report: &Report) -> Result<String> {
    serde_json::to_string_pretty(report).context("serialize report to JSON")
}

/// Render a self-contained HTML report. No external CSS, no JS, no remote
/// fonts — opens cleanly in airgapped environments and CI artifact viewers.
#[must_use]
pub fn render_html(report: &Report) -> String {
    let mut s = String::with_capacity(8 * 1024);
    write_header(&mut s, report);
    write_summary(&mut s, report);
    write_findings(&mut s, report);
    write_footer(&mut s);
    s
}

fn write_header(s: &mut String, report: &Report) {
    let _ = write!(
        s,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sentinel Analyzer report — {app}</title>
<style>{css}</style>
</head>
<body>
<header>
  <h1>Sentinel Analyzer report</h1>
  <dl class="meta">
    <dt>Project</dt><dd>{app}</dd>
    <dt>Root</dt><dd><code>{root}</code></dd>
    <dt>Scanned</dt><dd>{date}</dd>
    <dt>Sentinel</dt><dd>v{version}</dd>
  </dl>
</header>
"#,
        app = html_escape(&report.app_name),
        root = html_escape(&report.scan_root),
        date = html_escape(&report.scan_date.to_rfc3339()),
        version = html_escape(&report.sentinel_version),
        css = INLINE_CSS,
    );
}

fn write_summary(s: &mut String, report: &Report) {
    let summary = &report.summary;
    let _ = write!(
        s,
        r#"<section class="summary">
  <h2>Summary</h2>
  <ul class="severity-counts">
    <li class="sev-critical"><span class="count">{c}</span><span class="label">Critical</span></li>
    <li class="sev-high"><span class="count">{h}</span><span class="label">High</span></li>
    <li class="sev-medium"><span class="count">{m}</span><span class="label">Medium</span></li>
    <li class="sev-low"><span class="count">{l}</span><span class="label">Low</span></li>
    <li class="sev-info"><span class="count">{i}</span><span class="label">Info</span></li>
  </ul>
  <p class="total">Total findings: <strong>{total}</strong></p>
</section>
"#,
        c = summary.critical,
        h = summary.high,
        m = summary.medium,
        l = summary.low,
        i = summary.info,
        total = summary.total,
    );
}

fn write_findings(s: &mut String, report: &Report) {
    let _ = writeln!(s, r#"<section class="findings">"#);
    let _ = writeln!(s, "<h2>Findings</h2>");
    if report.findings.is_empty() {
        let _ = writeln!(s, r#"<p class="no-findings">No findings — clean run.</p>"#);
    } else {
        for f in &report.findings {
            write_one_finding(s, f);
        }
    }
    let _ = writeln!(s, "</section>");
}

fn write_one_finding(s: &mut String, f: &Finding) {
    let sev_class = severity_class(f.severity);
    let location_html = match f.location.as_ref() {
        Some(loc) => match loc.line {
            Some(line) => format!(
                "<code>{}</code>:<code>{}</code>",
                html_escape(&loc.file),
                line
            ),
            None => format!("<code>{}</code>", html_escape(&loc.file)),
        },
        None => String::from("<em>n/a</em>"),
    };
    let mut refs_html = String::new();
    for r in &f.references {
        let _ = write!(
            refs_html,
            r#"<li><a href="{href}" rel="noopener">{label}</a></li>"#,
            href = html_escape(r),
            label = html_escape(r),
        );
    }
    let _ = write!(
        s,
        r#"<article class="finding {sev_class}">
  <header>
    <span class="severity">{severity}</span>
    <h3>{title}</h3>
  </header>
  <dl>
    <dt>Id</dt><dd><code>{id}</code></dd>
    <dt>Tool</dt><dd>{tool}</dd>
    <dt>Component</dt><dd><code>{component}</code></dd>
    <dt>Location</dt><dd>{location}</dd>
  </dl>
  <h4>What's wrong</h4>
  <pre class="description">{description}</pre>
  <h4>How to fix</h4>
  <p class="suggestion">{suggestion}</p>
"#,
        sev_class = sev_class,
        severity = f.severity,
        title = html_escape(&f.title),
        id = html_escape(&f.id),
        tool = f.tool,
        component = html_escape(&f.component),
        location = location_html,
        description = html_escape(&f.description),
        suggestion = html_escape(&f.suggestion),
    );
    if !f.references.is_empty() {
        let _ = write!(
            s,
            "<h4>References</h4>\n<ul class=\"refs\">{refs_html}</ul>\n"
        );
    }
    let _ = writeln!(s, "</article>");
}

fn write_footer(s: &mut String) {
    let _ = writeln!(s, "</body></html>");
}

fn severity_class(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "sev-critical",
        Severity::High => "sev-high",
        Severity::Medium => "sev-medium",
        Severity::Low => "sev-low",
        Severity::Info => "sev-info",
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

const INLINE_CSS: &str = r"
  body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         margin: 0; padding: 2rem; background: #fafafa; color: #222; }
  header h1 { margin: 0 0 0.5rem; font-size: 1.6rem; }
  dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem;
            margin: 0 0 2rem; font-size: 0.92rem; }
  dl.meta dt { font-weight: 600; color: #555; }
  dl.meta dd { margin: 0; }
  section.summary { background: #fff; border: 1px solid #e3e3e3; border-radius: 6px;
                    padding: 1rem 1.5rem; margin-bottom: 2rem; }
  ul.severity-counts { list-style: none; padding: 0; margin: 0;
                       display: flex; gap: 1rem; flex-wrap: wrap; }
  ul.severity-counts li { display: flex; flex-direction: column; align-items: center;
                          padding: 0.5rem 1rem; border-radius: 4px;
                          min-width: 4.5rem; }
  ul.severity-counts .count { font-size: 1.4rem; font-weight: 700; }
  ul.severity-counts .label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }
  .sev-critical { background: #ffe5e5; color: #8a1a1a; }
  .sev-high     { background: #ffeed6; color: #8a4d10; }
  .sev-medium   { background: #fff5d6; color: #765a10; }
  .sev-low      { background: #e6f4ff; color: #0a4d80; }
  .sev-info     { background: #f0f0f0; color: #444; }
  p.total { margin: 1rem 0 0; }
  section.findings h2 { margin-top: 0; }
  article.finding { background: #fff; border-left: 4px solid #ccc;
                    border-radius: 4px; padding: 1rem 1.25rem; margin-bottom: 1rem;
                    box-shadow: 0 1px 0 rgba(0,0,0,0.04); }
  article.finding header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
  article.finding .severity { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px;
                              font-weight: 700; font-size: 0.78rem; letter-spacing: 0.05em; }
  article.finding.sev-critical { border-left-color: #c0392b; }
  article.finding.sev-critical .severity { background: #ffe5e5; color: #8a1a1a; }
  article.finding.sev-high     { border-left-color: #d9822b; }
  article.finding.sev-high     .severity { background: #ffeed6; color: #8a4d10; }
  article.finding.sev-medium   { border-left-color: #c9a014; }
  article.finding.sev-medium   .severity { background: #fff5d6; color: #765a10; }
  article.finding.sev-low      { border-left-color: #2b6cb0; }
  article.finding.sev-low      .severity { background: #e6f4ff; color: #0a4d80; }
  article.finding.sev-info     { border-left-color: #777; }
  article.finding.sev-info     .severity { background: #f0f0f0; color: #444; }
  article.finding h3 { margin: 0; font-size: 1.05rem; }
  article.finding h4 { margin: 0.75rem 0 0.25rem; font-size: 0.92rem; color: #444; }
  article.finding dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.2rem 1rem;
                       margin: 0.5rem 0; font-size: 0.9rem; }
  article.finding dl dt { color: #666; font-weight: 600; }
  article.finding dl dd { margin: 0; }
  article.finding pre.description { background: #fafafa; padding: 0.75rem 1rem;
                                    border: 1px solid #eee; border-radius: 4px;
                                    white-space: pre-wrap; word-break: break-word;
                                    font: 0.85rem/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }
  article.finding p.suggestion { margin: 0.25rem 0 0; }
  article.finding ul.refs { margin: 0.25rem 0 0 1.25rem; padding: 0; }
  article.finding ul.refs a { color: #0a4d80; }
  code { background: #f3f3f3; padding: 0.05em 0.3em; border-radius: 3px;
         font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .no-findings { color: #2b8a3e; font-weight: 500; }
";

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{Finding, Location, Tool};

    fn sample_report() -> Report {
        let f = Finding {
            id: "analyzer.webview.eval.src/App.tsx:5".to_string(),
            title: "eval() in webview".to_string(),
            description: "Bad <thing>".to_string(),
            severity: Severity::High,
            tool: Tool::Analyzer,
            component: "src/App.tsx".to_string(),
            suggestion: "Don't use eval".to_string(),
            location: Some(Location::new("src/App.tsx", Some(5))),
            references: vec!["https://example.com/eval".to_string()],
        };
        Report::new("demo", "/tmp/demo", vec![f])
    }

    #[test]
    fn render_json_round_trips() {
        let r = sample_report();
        let json = render_json(&r).unwrap();
        let parsed: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.app_name, "demo");
        assert_eq!(parsed.findings.len(), 1);
    }

    #[test]
    fn render_html_contains_critical_sections() {
        let r = sample_report();
        let html = render_html(&r);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<title>Sentinel Analyzer report"));
        assert!(html.contains("Total findings: <strong>1</strong>"));
        assert!(html.contains("eval() in webview"));
        assert!(html.contains("https://example.com/eval"));
        assert!(html.ends_with("</body></html>\n"));
    }

    #[test]
    fn render_html_escapes_html_in_finding_fields() {
        let r = sample_report();
        let html = render_html(&r);
        // The description had `<thing>` — must come out escaped.
        assert!(html.contains("&lt;thing&gt;"));
        assert!(!html.contains("Bad <thing>"));
    }

    #[test]
    fn render_html_handles_clean_run() {
        let r = Report::new("demo", "/tmp/x", vec![]);
        let html = render_html(&r);
        assert!(html.contains("No findings"));
        assert!(html.contains("Total findings: <strong>0</strong>"));
    }

    #[test]
    fn render_html_is_self_contained() {
        let html = render_html(&sample_report());
        // No remote URL inclusions. We allow `https://example.com` from references
        // (those are content), but no <link>, <script src=>, or remote fonts.
        assert!(!html.contains("<link "));
        assert!(!html.contains("<script src"));
        assert!(!html.contains("@import"));
    }
}
