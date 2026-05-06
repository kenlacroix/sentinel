# Getting started with Sentinel

This guide walks through installing Sentinel from source, running your first
unified scan, and wiring up the analyzer + fuzzer for deeper coverage.

## Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- A C toolchain (`build-essential` on Debian/Ubuntu, Xcode CLT on macOS, MSVC
  on Windows)
- `tar` available on your `$PATH` (used to unpack the RustSec advisory archive)

Optional, for the fuzzer:

- nightly Rust toolchain — `rustup toolchain install nightly`
- `cargo-fuzz` — `cargo install cargo-fuzz`

Run `cargo run -p sentinel -- doctor` once installed to confirm everything
is wired up.

## Build

```bash
git clone https://github.com/kenlacroix/sentinel.git
cd sentinel
cargo build --release
```

The unified `sentinel` binary lands at `target/release/sentinel`. The
standalone tool binaries (`sentinel-cartographer`, `sentinel-analyzer`,
`sentinel-fuzzer`) ship alongside it for users who want one capability
without the rest.

## First scan — unified

```bash
cargo run -p sentinel -- scan /path/to/your/tauri/project
```

This runs the cartographer (dependency CVEs + Tauri config audit) and the
analyzer (Tauri-aware static analysis) and merges every finding into one
report. The fuzzer is opt-in via `--fuzz <target>` because it needs nightly.

By default the cartographer downloads the RustSec advisory database into
`~/.sentinel/advisory-db/` on the first run. Subsequent scans reuse the
cache for 24 hours.

### Useful flags

```bash
sentinel scan ./project --no-advisories          # skip CVE matching, faster + offline
sentinel scan ./project --refresh-advisories     # force CVE cache refresh
sentinel scan ./project --no-cartographer        # analyzer-only run
sentinel scan ./project --no-analyzer            # cartographer-only run
sentinel scan ./project --fuzz store_mood --duration 60
sentinel scan ./project --format json -o report.json
sentinel scan ./project --format html -o report.html
```

The unified scan exits non-zero when any High or Critical finding appears,
so it works directly as a CI gate.

## Standalone tool — cartographer only

If you want just the cartographer (older docs and CI configs may reference
this form):

```bash
cargo run -p sentinel-cartographer -- /path/to/your/tauri/project
```

By default the cartographer downloads the RustSec advisory database into
`~/.sentinel/advisory-db/` on the first run. Subsequent scans reuse the
cache for 24 hours.

### Skip the advisory database

If you only need structural findings (CSP, allowlist, surface area):

```bash
cargo run -p sentinel-cartographer -- /path/to/project --no-advisories
```

### Force a cache refresh

```bash
cargo run -p sentinel-cartographer -- /path/to/project --refresh
```

### JSON output

```bash
cargo run -p sentinel-cartographer -- /path/to/project --format json > report.json
```

## What you'll see

The cartographer emits at minimum a `cartographer.surface.dependency_count`
informational finding. If your project disables CSP it adds a `high`-severity
`cartographer.tauri.csp_disabled`. If `tauri.allowlist.all = true` it adds a
`critical` `cartographer.tauri.allowlist_all`. Any matched advisory becomes a
`cartographer.cve.RUSTSEC-NNNN-NNNN` finding, severity inferred from the
advisory's CVSS string (defaulting to `high` when absent).

## Fuzzing your Tauri commands

Sentinel's fuzzer is a thin wrapper over [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html)
that targets `#[tauri::command]` handlers via [`tauri::test::mock_builder()`](https://docs.rs/tauri/latest/tauri/test/index.html).
You write one fuzz target per command you want fuzzed; Sentinel handles
discovery, the run, crash classification, and reporting.

### One-time toolchain setup

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
sentinel-fuzzer doctor   # confirms both are wired up
```

### Wire up your first fuzz target

From the root of your Tauri project:

```bash
cargo +nightly fuzz init   # creates fuzz/ subcrate with cargo-fuzz scaffolding
cargo +nightly fuzz add store_mood   # creates fuzz/fuzz_targets/store_mood.rs
```

Replace the generated `fuzz_targets/store_mood.rs` with the Sentinel template
at `crates/sentinel-fuzzer/templates/fuzz_target.rs.tmpl`, and adapt the
`<COMMAND>` and `FuzzInput` fields to match your real command and its arg
types. The template uses `tauri::test::mock_builder()` plus a `#[derive(Arbitrary)]`
input type, so libFuzzer produces structured inputs that pass through serde
deserialization and reach your handler logic.

In `fuzz/Cargo.toml` make sure `tauri` has the `test` feature enabled:

```toml
tauri = { version = "2", features = ["test"] }
```

### Run the fuzzer

```bash
sentinel-fuzzer run /path/to/project --target store_mood --duration 60
```

Pass `--format json` for a machine-readable report, `--seed N` for
reproducible runs, and `--list-targets` (as a separate subcommand) to
enumerate everything Sentinel found in `fuzz/fuzz_targets/`.

### What you'll see

A clean run prints `Clean run — no crashes detected.` and exits 0.

A run that finds a panic produces a `fuzzer.crash.panic.<hash>` finding with
severity **High** — panics in IPC handlers are reachable by anything that
can talk to the webview, which makes them at minimum a remote DoS.
Sanitizer reports become **Critical**, OOM and timeout become **Medium**.
The finding's description includes the exact `cargo +nightly fuzz run`
command needed to reproduce.

The fuzzer exits non-zero when it produces any High or Critical finding, so
CI can gate on `sentinel-fuzzer run` directly.

## Analyzing your Tauri source

The analyzer is a Tauri-aware static security scanner. It does **not** try to
be a generic secret scanner — for that, install
[gitleaks](https://github.com/gitleaks/gitleaks) or
[trufflehog](https://github.com/trufflesecurity/trufflehog), which ship 5000+
tuned patterns and live verifier callbacks.

Sentinel focuses on patterns no generic tool catches well: command-injection
sinks reachable from `#[tauri::command]` handlers, path-traversal sinks,
`eval()` in webview code, `dangerouslySetInnerHTML` over IPC data,
`unsafe` blocks inside command handlers, weak crypto, plain HTTP, and CSP
weaknesses.

### Run the analyzer

```bash
sentinel-analyzer /path/to/your/tauri/project
```

Output formats:

```bash
sentinel-analyzer ./project --format text      # default; pretty terminal
sentinel-analyzer ./project --format json -o report.json
sentinel-analyzer ./project --format html -o report.html
```

The HTML report is fully self-contained (embedded CSS, no remote assets) so
it opens cleanly from email, S3, CI artifact viewers, or airgapped envs.

### What you'll see

| Severity | Examples |
| --- | --- |
| Critical | `tauri.command_injection` — a `#[tauri::command]` argument flows into `Command::new(...)` |
| High     | `tauri.path_traversal`, `webview.eval`, `webview.dangerously_set_inner_html`, `tauri.csp_unsafe_eval` |
| Medium   | `crypto.weak_hash`, `network.http_in_fetch`, `tauri.unsafe_in_command` |

The analyzer exits non-zero when any High or Critical finding appears, so
`sentinel-analyzer ./project` works directly as a CI gate.

### Suppressing false positives

Inline comments turn off matches with surgical precision:

```rust
let h = Md5::new();  // sentinel:ignore-rule:crypto.weak_hash
```

Forms accepted:

```text
// sentinel:ignore                       — silence ALL rules on this line
// sentinel:ignore-next-line             — silence ALL rules on the next line
// sentinel:ignore-rule:webview.eval     — silence one rule on this line
// sentinel:ignore-rule:a.b,c.d          — silence multiple rules
```

Block-comment forms (`/* sentinel:ignore */`) work too.

For path-level exclusions, drop a `.sentinelignore` at the project root.
Same shape as `.gitignore`:

```text
# project root
src/legacy/
*.bak
**/generated/*
```

### Custom rules

Pass `--rules path/to/rules.toml` to extend or override the built-in
pattern library:

```toml
[[patterns]]
id = "myorg.no_panic_in_command"
kind = "regex"
title = "panic!() inside a Tauri command body"
description = "We disallow panics in command handlers — they crash the webview."
severity = "high"
suggestion = "Return Result<T, MyError> instead and let the frontend surface the error."
extensions = ["rs"]
regex = '''panic!\s*\('''
```

User rules with the same id as a built-in win, with a warning logged.

## Environment variables

- `SENTINEL_HOME` — override the cache root (default `~/.sentinel`)
- `RUST_LOG=info` — enable info-level tracing output

## Troubleshooting

- **"failed to spawn tar"** — install `tar` (`apt-get install tar` /
  `brew install gnu-tar`). A native unpack path is on the roadmap.
- **"advisory store is empty"** — run once with `--refresh` to populate the
  cache, or pass `--no-advisories` if you don't need CVE matching.
- **"no Cargo.toml found"** — the cartographer searches up to 6 levels deep
  from the supplied path. Point it at the workspace root, not a subdirectory.
- **"cargo-fuzz is not installed"** — run `sentinel-fuzzer doctor`. It will
  print install commands for both `cargo-fuzz` and the nightly toolchain.
- **"no fuzz/ subcrate"** — run `cargo +nightly fuzz init` from the project
  root before invoking `sentinel-fuzzer run`.
- **"fuzz target X not found"** — Sentinel only sees files under
  `fuzz/fuzz_targets/`. Run `sentinel-fuzzer list-targets <project>` to see
  what it discovered.
- **Analyzer reports a finding inside a comment** — block comments
  (`/* ... */`) spanning multiple lines aren't always recognised by the
  regex pass. Use `// sentinel:ignore-rule:<id>` on the line, or rephrase
  the comment so it doesn't include a literal `eval(` / `Command::new(`
  / etc.
- **Analyzer misses a real bug behind a helper function** — Sentinel's
  dataflow tracer is bounded to single-function scope by design.
  Cross-function flow lands in the `analyzer.tree-sitter` deferred TODO.
