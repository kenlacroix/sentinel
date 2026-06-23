# Sentinel

Security auditor for Tauri applications and cross-platform distributed apps.

One CLI, three integrated tools, one merged report.

## Tools

- **cartographer** — dependency CVE matching (RustSec) + Tauri config audit (CSP, allowlist)
- **analyzer** — Tauri-aware static analysis: command-injection sinks reachable from `#[tauri::command]`, path-traversal, webview `eval` / `dangerouslySetInnerHTML`, weak crypto, plain HTTP, CSP weakness
- **fuzzer** — IPC behavioral fuzzing on top of `cargo-fuzz` + `tauri::test::mock_builder`

Generic secret scanning is intentionally delegated to [gitleaks](https://github.com/gitleaks/gitleaks) and [trufflehog](https://github.com/trufflesecurity/trufflehog) — they do that better than Sentinel ever could.

## Status

Early development. Targeting v0.1.0-alpha at Week 8.

## Quick start

```bash
cargo build --release

# Check toolchain status
cargo run -p sentinel -- doctor

# Run all tools at once and emit a merged report
cargo run -p sentinel -- scan /path/to/your/tauri/project

# JSON or self-contained HTML output
cargo run -p sentinel -- scan ./project --format html -o report.html
```

Each tool is also installable as its own standalone binary
(`sentinel-cartographer`, `sentinel-analyzer`, `sentinel-fuzzer`) for users
who want one capability without the rest. See [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md).

## License

MIT

---

Built by [Kenneth LaCroix](https://kennethlacroix.me)
