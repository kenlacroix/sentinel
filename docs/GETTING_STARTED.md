# Getting started with Sentinel

This guide walks through installing Sentinel from source and running your
first cartographer scan.

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
