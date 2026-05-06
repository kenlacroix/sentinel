//! CVE / advisory cross-reference for cartographer findings.
//!
//! ## Data sources
//!
//! Sentinel uses the [RustSec advisory database](https://rustsec.org/) as the
//! canonical source for Rust crate vulnerabilities. `RustSec` is free, requires
//! no API key, and is the same database `cargo audit` consumes — it
//! aggregates CVE/GHSA references and crate-level affected ranges.
//!
//! Advisories are downloaded from
//! `https://github.com/rustsec/advisory-db/archive/refs/heads/main.tar.gz`
//! and cached locally under `$SENTINEL_HOME/advisory-db/`. The cache is
//! considered fresh for 24h by default.
//!
//! ## Offline-first
//!
//! Once downloaded, all matching happens locally. The fetcher is opt-in: pass
//! `refresh = true` to update the cache, otherwise the cartographer reads
//! whatever is on disk. Tests use a fixture loader to avoid network access.

use anyhow::{Context, Result};
use chrono::Utc;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

const ADVISORY_DB_URL: &str =
    "https://github.com/rustsec/advisory-db/archive/refs/heads/main.tar.gz";
const DEFAULT_CACHE_TTL_SECS: i64 = 24 * 60 * 60;

/// Outcome of consulting the on-disk advisory cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    /// Cache is present and within the freshness window.
    Fresh,
    /// Cache is present but older than the configured TTL.
    Stale,
    /// No cache directory exists yet.
    Missing,
}

/// A normalized advisory describing a vulnerability against one crate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Advisory {
    /// `RustSec` id, e.g. `RUSTSEC-2024-0001`.
    pub id: String,
    /// Affected crate name (crates.io package name).
    pub package: String,
    /// Short title from the advisory.
    pub title: String,
    /// Long-form description.
    pub description: String,
    /// CVSS or severity string when present (`"critical"`, `"high"`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Semver requirement strings describing affected versions.
    pub patched_versions: Vec<String>,
    /// Semver requirement strings describing unaffected versions.
    pub unaffected_versions: Vec<String>,
    /// CVE / GHSA aliases.
    pub aliases: Vec<String>,
    /// Reference URLs.
    pub references: Vec<String>,
}

impl Advisory {
    /// Returns true if the supplied semver `version` is affected by this advisory.
    ///
    /// The matcher is conservative: if a version requirement does not parse,
    /// or the input is not a valid semver, we treat the advisory as
    /// **possibly affected** so the cartographer over-reports rather than
    /// silently missing a vulnerability.
    #[must_use]
    pub fn matches_version(&self, version: &str) -> bool {
        let Ok(parsed) = Version::parse(strip_metadata(version)) else {
            return true;
        };

        for req in &self.unaffected_versions {
            if let Ok(vr) = VersionReq::parse(req) {
                if vr.matches(&parsed) {
                    return false;
                }
            }
        }
        for req in &self.patched_versions {
            if let Ok(vr) = VersionReq::parse(req) {
                if vr.matches(&parsed) {
                    return false;
                }
            }
        }
        true
    }
}

fn strip_metadata(s: &str) -> &str {
    s.split_once('+').map_or(s, |(left, _)| left)
}

/// In-memory advisory index keyed by crate name.
#[derive(Debug, Clone, Default)]
pub struct AdvisoryStore {
    by_package: HashMap<String, Vec<Advisory>>,
}

impl AdvisoryStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an advisory into the store.
    pub fn insert(&mut self, advisory: Advisory) {
        self.by_package
            .entry(advisory.package.clone())
            .or_default()
            .push(advisory);
    }

    /// Number of advisories in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_package.values().map(Vec::len).sum()
    }

    /// `true` if the store has no advisories.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_package.is_empty()
    }

    /// Return all advisories that match `crate_name` and `version`.
    #[must_use]
    pub fn matches(&self, crate_name: &str, version: &str) -> Vec<&Advisory> {
        let Some(candidates) = self.by_package.get(crate_name) else {
            return vec![];
        };
        candidates
            .iter()
            .filter(|a| a.matches_version(version))
            .collect()
    }

    /// Load every advisory file from a directory tree (recursive).
    ///
    /// `RustSec` stores advisories as TOML files at
    /// `<root>/crates/<crate-name>/<RUSTSEC-id>.toml`. We accept any layout
    /// that yields parseable advisory TOMLs.
    ///
    /// # Errors
    ///
    /// Propagates IO errors. Individual malformed files are logged and skipped
    /// rather than failing the whole load.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        let mut store = Self::new();
        if !dir.exists() {
            return Ok(store);
        }
        for entry in walkdir::WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            // Real RustSec advisories all start with `RUSTSEC-`. This filter
            // skips db-internal files like EXAMPLE_ADVISORY.md, support.toml,
            // and HOWTO_*.md that share the directory.
            if !stem.starts_with("RUSTSEC-") {
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "toml" && ext != "md" {
                continue;
            }
            let raw = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "skip unreadable advisory");
                    continue;
                }
            };
            // Markdown advisories embed the TOML metadata in a fenced
            // ```toml ... ``` block at the top of the file. The actual
            // title lives as the first H1 heading after the fence.
            let (toml_src, md_title) = if ext == "md" {
                let Some(toml) = extract_toml_block(&raw) else {
                    tracing::warn!(
                        path = %path.display(),
                        "skip advisory with no toml fenced block"
                    );
                    continue;
                };
                (toml, extract_first_h1(&raw))
            } else {
                (raw.clone(), None)
            };
            match parse_rustsec_toml(&toml_src) {
                Ok(mut adv) => {
                    if let Some(t) = md_title {
                        adv.title = t;
                    }
                    store.insert(adv);
                }
                Err(e) => tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "skip unparseable advisory"
                ),
            }
        }
        Ok(store)
    }
}

/// Extract the contents of the first ```` ```toml ```` fenced block in a
/// markdown advisory. `RustSec` stores its metadata that way as of 2024+ —
/// the `.md` file is markdown prose with the structured TOML header at
/// the top, between fence markers.
fn extract_toml_block(raw: &str) -> Option<String> {
    // Find the opening fence.
    let after_open = raw
        .find("```toml")
        .map(|i| i + "```toml".len())
        .or_else(|| raw.find("```TOML").map(|i| i + "```TOML".len()))?;
    let rest = &raw[after_open..];
    // Skip the optional newline after the fence opener.
    let body_start = rest.find('\n').map_or(0, |n| n + 1);
    let body = &rest[body_start..];
    let close = body.find("```")?;
    Some(body[..close].to_string())
}

/// Extract the first markdown `# Heading` line as a title.
///
/// Looks past any leading TOML fenced block. Skips lines that begin with
/// more than one `#` (those are subheadings, not the document title).
fn extract_first_h1(raw: &str) -> Option<String> {
    let after_fence = raw
        .find("```toml")
        .or_else(|| raw.find("```TOML"))
        .and_then(|start| raw[start + 7..].find("```").map(|c| start + 7 + c + 3))
        .unwrap_or(0);
    for line in raw[after_fence..].lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("# ") {
            let title = rest.trim();
            if !title.is_empty() {
                return Some(title.to_string());
            }
        }
    }
    None
}

/// HTTP client that downloads and unpacks the `RustSec` advisory database.
pub struct NvdClient {
    cache_dir: PathBuf,
    ttl: Duration,
    client: reqwest::Client,
}

impl NvdClient {
    /// Construct a client that caches advisories under `cache_dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying HTTP client cannot be constructed.
    pub fn new(cache_dir: PathBuf) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("sentinel-cartographer/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_mins(1))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            cache_dir,
            ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS as u64),
            client,
        })
    }

    /// Override the freshness TTL used by [`NvdClient::cache_status`].
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Path on disk where advisories are unpacked.
    #[must_use]
    pub fn cache_path(&self) -> &Path {
        &self.cache_dir
    }

    /// Inspect the cache directory.
    #[must_use]
    pub fn cache_status(&self) -> CacheStatus {
        let stamp = self.cache_dir.join(".last_update");
        let Ok(meta) = std::fs::metadata(&stamp) else {
            return CacheStatus::Missing;
        };
        let Ok(modified) = meta.modified() else {
            return CacheStatus::Missing;
        };
        let elapsed = modified.elapsed().unwrap_or(Duration::from_secs(0));
        if elapsed <= self.ttl {
            CacheStatus::Fresh
        } else {
            CacheStatus::Stale
        }
    }

    /// Ensure the on-disk cache is populated.
    ///
    /// If `force_refresh` is true, the cache is always re-downloaded.
    /// Otherwise, a fresh cache is left untouched.
    ///
    /// # Errors
    ///
    /// Returns an error if the network request fails or the archive is
    /// malformed.
    pub async fn refresh(&self, force_refresh: bool) -> Result<()> {
        if !force_refresh && self.cache_status() == CacheStatus::Fresh {
            return Ok(());
        }
        sentinel_core::io::ensure_dir(&self.cache_dir)?;
        let bytes = self
            .client
            .get(ADVISORY_DB_URL)
            .send()
            .await
            .context("download advisory archive")?
            .error_for_status()
            .context("advisory archive returned non-success")?
            .bytes()
            .await
            .context("read advisory archive body")?;

        unpack_archive(&bytes, &self.cache_dir).context("unpack advisory archive")?;
        let stamp = self.cache_dir.join(".last_update");
        std::fs::write(&stamp, Utc::now().to_rfc3339()).context("write cache stamp")?;
        Ok(())
    }

    /// Load all cached advisories into an in-memory store.
    ///
    /// # Errors
    ///
    /// Returns an error if traversal fails. Malformed individual files are
    /// skipped with a warning.
    pub fn load_store(&self) -> Result<AdvisoryStore> {
        AdvisoryStore::load_from_dir(&self.cache_dir)
    }
}

fn unpack_archive(bytes: &[u8], dest: &Path) -> Result<()> {
    // The `tar` + `flate2` dependencies aren't included in the core build to
    // keep compile time low. For the MVP we shell out to the system `tar`,
    // which is universally available on developer machines and CI runners.
    // If this ever needs to run in environments without `tar`, swap in
    // `flate2::read::GzDecoder` + `tar::Archive`.
    use std::io::Write;
    use std::process::{Command, Stdio};

    sentinel_core::io::ensure_dir(dest)?;
    let mut child = Command::new("tar")
        .arg("-xzf")
        .arg("-")
        .arg("-C")
        .arg(dest)
        .arg("--strip-components=1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn tar; install tar or implement native unpack")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(bytes)
            .context("write archive to tar stdin")?;
    }
    let output = child.wait_with_output().context("wait for tar")?;
    if !output.status.success() {
        anyhow::bail!(
            "tar exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// Parse a single `RustSec` advisory TOML file into our normalized form.
///
/// # Errors
///
/// Returns an error if the input is not valid TOML or is missing required
/// fields (`advisory.id`, `advisory.package`, `advisory.title`).
pub fn parse_rustsec_toml(raw: &str) -> Result<Advisory> {
    use toml::Value;

    let doc: Value = toml::from_str(raw).context("not valid TOML")?;

    let advisory = doc
        .get("advisory")
        .and_then(Value::as_table)
        .context("missing [advisory] table")?;

    let id = advisory
        .get("id")
        .and_then(Value::as_str)
        .context("missing advisory.id")?
        .to_string();
    let package = advisory
        .get("package")
        .and_then(Value::as_str)
        .context("missing advisory.package")?
        .to_string();
    // RustSec advisories store the title as a markdown `#` heading in the
    // body, not in the TOML metadata. The parser tolerates a missing title
    // and falls back to the advisory id; `load_from_dir` overrides this
    // with the markdown heading when it has one.
    let title = advisory
        .get("title")
        .and_then(Value::as_str)
        .map_or_else(|| id.clone(), str::to_string);
    let description = advisory
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let severity = advisory
        .get("cvss")
        .and_then(Value::as_str)
        .map(str::to_string);
    let aliases = string_list(advisory, "aliases");
    let references = string_list(advisory, "references");

    let versions = doc.get("versions").and_then(Value::as_table);
    let patched_versions = versions
        .and_then(|t| t.get("patched"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let unaffected_versions = versions
        .and_then(|t| t.get("unaffected"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(Advisory {
        id,
        package,
        title,
        description,
        severity,
        patched_versions,
        unaffected_versions,
        aliases,
        references,
    })
}

fn string_list(table: &toml::map::Map<String, toml::Value>, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_advisory(id: &str, package: &str, patched: &[&str]) -> Advisory {
        Advisory {
            id: id.to_string(),
            package: package.to_string(),
            title: format!("title for {id}"),
            description: format!("description for {id}"),
            severity: Some("high".to_string()),
            patched_versions: patched.iter().map(|s| (*s).to_string()).collect(),
            unaffected_versions: vec![],
            aliases: vec![],
            references: vec![],
        }
    }

    #[test]
    fn matches_version_returns_true_when_below_patched() {
        let a = sample_advisory("RUSTSEC-1", "demo", &[">=1.2.3"]);
        assert!(a.matches_version("1.2.0"));
    }

    #[test]
    fn matches_version_returns_false_when_in_patched_range() {
        let a = sample_advisory("RUSTSEC-1", "demo", &[">=1.2.3"]);
        assert!(!a.matches_version("1.2.3"));
        assert!(!a.matches_version("2.0.0"));
    }

    #[test]
    fn matches_version_overrules_with_unaffected() {
        let mut a = sample_advisory("RUSTSEC-1", "demo", &[">=1.2.3"]);
        a.unaffected_versions = vec!["<1.0.0".to_string()];
        assert!(!a.matches_version("0.5.0"));
        assert!(a.matches_version("1.0.0"));
    }

    #[test]
    fn matches_version_treats_unparseable_as_potentially_affected() {
        let a = sample_advisory("RUSTSEC-1", "demo", &[">=1.2.3"]);
        assert!(a.matches_version("not-a-version"));
    }

    #[test]
    fn store_indexes_by_package() {
        let mut store = AdvisoryStore::new();
        store.insert(sample_advisory("RUSTSEC-1", "alpha", &[">=2.0"]));
        store.insert(sample_advisory("RUSTSEC-2", "beta", &[">=3.0"]));
        store.insert(sample_advisory("RUSTSEC-3", "alpha", &[">=4.0"]));

        assert_eq!(store.len(), 3);
        assert_eq!(store.matches("alpha", "1.0.0").len(), 2);
        assert_eq!(store.matches("beta", "1.0.0").len(), 1);
        assert_eq!(store.matches("ghost", "1.0.0").len(), 0);
    }

    #[test]
    fn parse_rustsec_toml_extracts_fields() {
        let raw = r#"
            [advisory]
            id = "RUSTSEC-2024-0001"
            package = "demo-crate"
            title = "Buffer overflow"
            description = "A buffer overflow in version X."
            cvss = "high"
            aliases = ["CVE-2024-0001", "GHSA-aaaa-bbbb-cccc"]
            references = ["https://example.com/advisory"]

            [versions]
            patched = [">=1.4.0"]
            unaffected = ["<1.0.0"]
        "#;
        let adv = parse_rustsec_toml(raw).unwrap();
        assert_eq!(adv.id, "RUSTSEC-2024-0001");
        assert_eq!(adv.package, "demo-crate");
        assert!(adv.aliases.contains(&"CVE-2024-0001".to_string()));
        assert_eq!(adv.patched_versions, vec![">=1.4.0".to_string()]);
        assert_eq!(adv.unaffected_versions, vec!["<1.0.0".to_string()]);
        assert!(adv.matches_version("1.2.0"));
        assert!(!adv.matches_version("1.4.0"));
        assert!(!adv.matches_version("0.9.0"));
    }

    #[test]
    fn parse_rustsec_toml_falls_back_to_id_when_title_missing() {
        let raw = r#"
            [advisory]
            id = "RUSTSEC-2025-0004"
            package = "openssl"

            [versions]
            patched = [">= 0.10.70"]
        "#;
        let adv = parse_rustsec_toml(raw).unwrap();
        assert_eq!(adv.title, "RUSTSEC-2025-0004");
    }

    #[test]
    fn extract_first_h1_finds_title_after_toml_fence() {
        let md = "```toml\n[advisory]\nid = \"X\"\npackage = \"y\"\n```\n\n# Real title here\n\nBody text.\n";
        assert_eq!(extract_first_h1(md).as_deref(), Some("Real title here"));
    }

    #[test]
    fn extract_first_h1_skips_subheadings_and_returns_none_if_absent() {
        assert_eq!(extract_first_h1("body with no heading"), None);
        // Subheading shouldn't match before the H1.
        let md = r"```toml
x = 1
```
## Subheading first
# Real title
";
        assert_eq!(extract_first_h1(md).as_deref(), Some("Real title"));
    }

    #[test]
    fn load_from_dir_recursively_collects_advisories() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("crates").join("demo");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("RUSTSEC-2024-0001.toml"),
            r#"
                [advisory]
                id = "RUSTSEC-2024-0001"
                package = "demo"
                title = "x"
                [versions]
                patched = [">=1.0.0"]
            "#,
        )
        .unwrap();
        // Junk files should be skipped without error.
        std::fs::write(nested.join("README.md"), "ignore me").unwrap();
        std::fs::write(nested.join("EXAMPLE_ADVISORY.md"), "ignore").unwrap();
        std::fs::write(nested.join("support.toml"), "irrelevant = true").unwrap();
        // Real-shape filename but bad TOML: should warn-and-skip, not panic.
        std::fs::write(
            nested.join("RUSTSEC-2024-9999.toml"),
            "this is not advisory toml",
        )
        .unwrap();

        let store = AdvisoryStore::load_from_dir(tmp.path()).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.matches("demo", "0.9.0").len(), 1);
    }

    #[test]
    fn load_from_dir_parses_modern_markdown_frontmatter() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("crates").join("openssl");
        std::fs::create_dir_all(&nested).unwrap();
        // RustSec's modern format: TOML metadata fenced inside markdown,
        // with the human-readable title in the markdown body — NOT the TOML.
        std::fs::write(
            nested.join("RUSTSEC-2025-0004.md"),
            r#"```toml
[advisory]
id = "RUSTSEC-2025-0004"
package = "openssl"
aliases = ["CVE-2025-24898"]

[versions]
patched = [">= 0.10.70"]
```

# ssl::select_next_proto use after free

Long-form prose follows here, which the parser must ignore.
"#,
        )
        .unwrap();

        let store = AdvisoryStore::load_from_dir(tmp.path()).unwrap();
        assert_eq!(store.len(), 1, "should parse the markdown advisory");
        let matches = store.matches("openssl", "0.10.50");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "RUSTSEC-2025-0004");
        assert!(matches[0].aliases.iter().any(|a| a == "CVE-2025-24898"));
        assert_eq!(
            matches[0].title, "ssl::select_next_proto use after free",
            "title should come from the markdown H1"
        );
    }

    #[test]
    fn extract_toml_block_handles_lowercase_and_uppercase_fence() {
        assert_eq!(
            extract_toml_block("```toml\nx = 1\n```\n# rest\n").as_deref(),
            Some("x = 1\n")
        );
        assert_eq!(
            extract_toml_block("```TOML\ny = 2\n```").as_deref(),
            Some("y = 2\n")
        );
    }

    #[test]
    fn extract_toml_block_returns_none_when_no_fence() {
        assert_eq!(extract_toml_block("# pure markdown\nno toml here"), None);
    }

    #[test]
    fn load_from_dir_returns_empty_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let store = AdvisoryStore::load_from_dir(&missing).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn cache_status_reports_missing_for_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let client = NvdClient::new(tmp.path().to_path_buf()).unwrap();
        assert_eq!(client.cache_status(), CacheStatus::Missing);
    }
}
