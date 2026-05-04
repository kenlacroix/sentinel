# Getting started with Sentinel

This guide walks through installing Sentinel from source, running your first
cartographer scan, and wiring up a fuzz target for the IPC fuzzer.

## Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- A C toolchain (`build-essential` on Debian/Ubuntu, Xcode CLT on macOS, MSVC
  on Windows)
- `tar` available on your `$PATH` (used to unpack the RustSec advisory archive)

## Build

```bash
git clone https://github.com/kenlacroix/sentinel.git
cd sentinel
cargo build --release
```

The cartographer binary lands at `target/release/sentinel-cartographer`.

## First scan

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
