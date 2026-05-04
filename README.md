# Sentinel

Security auditor for Tauri applications and cross-platform distributed apps.

## Components

- **sentinel-cartographer** — attack surface + dependency CVE mapping
- **sentinel-fuzzer** — IPC behavioral fuzzing
- **sentinel-analyzer** — security pattern detection

## Status

Early development. Targeting v0.1.0-alpha at Week 8.

## Quick start

```bash
cargo build --release
cargo run -p sentinel-cartographer -- <path-to-tauri-project>
```

## License

MIT
