# Sentinel architecture

Sentinel is a Cargo workspace of four crates that emit and consume a shared
`Report` type defined in `sentinel-core`.

```
                         ┌──────────────────┐
                         │  sentinel-core   │
                         │  Report types    │
                         └────────▲─────────┘
                                  │
       ┌──────────────────────────┼──────────────────────────┐
       │                          │                          │
┌──────┴───────┐         ┌────────┴────────┐         ┌───────┴────────┐
│ cartographer │         │     fuzzer      │         │    analyzer    │
│ deps + CVEs  │         │  IPC mutation   │         │  patterns/AST  │
└──────┬───────┘         └─────────────────┘         └────────────────┘
       │
       ▼
~/.sentinel/advisory-db   (cached RustSec advisories)
```

## Crates

### `sentinel-core`

Defines the canonical types every other crate emits:

- `Severity` — ordered enum (`Info < Low < Medium < High < Critical`)
- `Tool` — which tool produced a finding
- `Finding` — id, title, description, severity, suggestion, location, refs
- `ScanSummary` — pre-computed counts
- `Report` — top-level container

Also exposes `sentinel_core::io` helpers for the `$SENTINEL_HOME` cache root.

### `sentinel-cartographer` (Week 1-2)

Three modules:

- `parser` — walks the project, parses every `Cargo.toml` and
  `tauri.conf.json`/`tauri.conf.json5`. Skips `target/`, `node_modules/`,
  `.git/`, `dist/`, `build/`, `.next/`, `.svelte-kit/`, `out/`. Caps depth at
  6 to defeat symlink loops. Tolerant of Tauri v1 (`tauri.allowlist`) and v2
  (`app.security.capabilities`, `plugins.*`) schemas.
- `cve` — downloads the [RustSec advisory database](https://rustsec.org/) into
  `$SENTINEL_HOME/advisory-db/`, with a 24h freshness window. Uses RustSec
  rather than the NVD API because it is free, requires no API key, has
  crate-level affected-version semantics, and is the canonical source
  `cargo audit` consumes.
- `scan` — orchestrates parser + advisory store and emits `Finding`s for
  vulnerable dependencies, disabled CSP, `allowlist.all = true`, and a
  surface-area summary.

The CLI binary (`src/main.rs`) wraps `scan::cartograph` with `clap`,
producing either text or JSON output.

### `sentinel-fuzzer` (Week 3 — stub today)

Will implement mutation-based fuzzing of Tauri command handlers: bitflip,
byte mutation, interesting values, dictionary, and havoc strategies driving a
test harness that catches panics via `std::panic::catch_unwind`. Crashing
inputs are minimized and persisted.

### `sentinel-analyzer` (Week 4 — stub today)

Will implement regex-pattern detection for hardcoded keys, weak crypto, and
insecure URLs, plus a simple grep-based dataflow tracer. HTML report
generator emits a single self-contained file embedding findings + styled
chrome.

## Severity model

Severity levels follow the OWASP-aligned scale, ordered by impact and
exploitability:

| Severity   | Meaning                                                    |
|------------|------------------------------------------------------------|
| `info`     | Non-actionable signal (e.g. dependency count)              |
| `low`      | Hardening opportunity                                       |
| `medium`   | Exploitable under specific conditions                       |
| `high`     | Readily exploitable, sensitive data exposure                |
| `critical` | Remote unauthenticated impact or full host compromise       |

When an advisory does not declare a severity, the cartographer defaults to
`high` so the user notices.

## Cache layout

```
$SENTINEL_HOME/                    # default: ~/.sentinel
└── advisory-db/                    # unpacked rustsec/advisory-db
    ├── .last_update                # rfc3339 stamp file
    └── crates/
        └── <crate>/RUSTSEC-XXXX-NNNN.toml
```

`SENTINEL_HOME` overrides the default location for tests and CI.
