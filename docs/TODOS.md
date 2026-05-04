# TODOS

Deferred work captured during plan / code review. Each item lists the why,
the tradeoffs, and any prerequisites. Items are deliberately deferred —
not silently dropped — so future planning sessions can see what was
considered.

## fuzzer.auto-discovery

**What:** Auto-discover `#[tauri::command]`-annotated functions in the user's
crate via `syn` parsing of source files, generate fuzz targets transitively,
eliminate the per-command harness file the convention-based MVP requires.

**Why:** Reduces user friction from "write a fuzz target per command" to
"point Sentinel at your project." Strong DX win once the fuzzer has shipped
and proven its value on real bugs.

**Pros:**
- Zero per-command setup; matches the cartographer's UX (point at a path).
- Removes the need to keep harness files in sync with command signature drift.

**Cons:**
- Source parsing is fragile to `macro_rules!` re-exports, workspace layouts,
  and proc-macro-defined commands.
- Argument types still need `#[derive(Arbitrary)]`; auto-discovery can't
  fix that without modifying user code.
- ~1 week of careful engineering (syn + ast walking + cargo metadata).

**Context:** The Week 3 MVP picked the convention-based path (user writes
`fuzz/fuzz_targets/<command>.rs` from a Sentinel template). That gets the
fuzzer shipping in 3 days and produces real bugs. Auto-discovery is the
polish layer once we know users actually adopt the fuzzer.

**Depends on / blocked by:** Week 3 fuzzer MVP must land first. Should pair
with a `cargo metadata`-based command-list cache so we don't re-parse on
every run.

## fuzzer.differential

**What:** Differential fuzzing between two versions of the same Tauri command
handler. Catches *behavior* regressions, not just crashes — same input
produces different outputs across versions.

**Why:** This is the strongest commercial hook in the roadmap. "Sentinel
told me my refactor of `process_payment` changed behavior on inputs X, Y, Z"
is a story enterprise customers will pay for.

**Pros:**
- Phase 3 SaaS positioning (continuous monitoring, version-bump confidence).
- Catches a class of bugs unit tests routinely miss (same return type,
  different distribution of return values).
- Composes cleanly with libFuzzer's corpus — one corpus, two binaries,
  diff the outputs.

**Cons:**
- Requires building two binaries (old + new) and managing both at runtime.
- Output equality is undecidable for non-deterministic handlers — needs a
  user-supplied normalizer.
- Defining "different enough" is a UX problem (false-positive risk if too
  strict, false-negative if too loose).

**Context:** Listed in Phase 2 of the master roadmap. Right time to build
this is after Week 5 MoodBloom audit demonstrates the basic fuzzer finds
real bugs — that proof-point makes the differential case easy to sell.

**Depends on / blocked by:** Week 3 fuzzer MVP. Phase 2 cloud-fuzzing
infrastructure (Phase 3 deliverable) will want this baked in.

## fuzzer.sandbox

**What:** A `#[fuzz_skip]` attribute macro plus a `--dry-run` mode that
detects destructive command names (heuristic match: `delete_*`, `clear_*`,
`drop_*`, `wipe_*`) and warns or skips them by default.

**Why:** Today, fuzzing a Tauri command that wipes the user's database is
the user's problem to remember. That's a footgun that will eventually hit
someone in CI and lose data.

**Pros:**
- Defensive default — the destructive-command-named-on-the-tin case gets
  caught automatically.
- `#[fuzz_skip]` is an explicit opt-out for users who really do want to
  fuzz a delete handler against a sandbox database.

**Cons:**
- Heuristic naming is approximate; misses `forget_user`, `purge_logs`.
- Adds a proc-macro dep to Sentinel — extra compile time for users.

**Context:** Currently mitigated by user discipline — they only write fuzz
targets for safe commands. Once the fuzzer has a wider user base, this will
show up as an incident report and we'll wish we'd shipped it earlier.

**Depends on / blocked by:** Week 3 fuzzer MVP. Independent of the other
two TODOs.

## analyzer.tree-sitter

**What:** Replace the regex-based pattern matcher with tree-sitter AST
queries. Unlocks cross-function dataflow (helper functions, call graphs),
struct field tracking, macro-expansion-aware matching, and pattern
specificity that regex can't express ("an `Arc<Mutex<T>>` whose inner
type is a sensitive struct").

**Why:** The Week 4 MVP intentionally limits dataflow to single-function
scope because that's where regex actually works. The hard part of
real-world taint analysis (a `#[tauri::command]` argument flowing through
three helpers and ending up in `Command::new`) is the part regex can't
do. Tree-sitter is the standard answer (semgrep uses it, github code
scanning uses it).

**Pros:**
- Catches the bugs regex can't: cross-function flow, struct field access,
  pattern specificity over types not just identifiers.
- Compounds with `fuzzer.auto-discovery` — that work also wants AST
  introspection of `#[tauri::command]` annotations.
- `tree-sitter-rust` and `tree-sitter-typescript` are mature crates
  with stable grammars; integration is incremental, not a rewrite.

**Cons:**
- Significantly more engineering than regex (~1-2 weeks).
- Each language grammar is its own parser to vendor + version-pin.
- Performance characteristics differ (regex is O(n) per pattern, AST
  walk is O(file size) with constant factor).

**Context:** Week 4 ships regex with single-function dataflow scope. The
bullet-point promise of "cross-function taint tracing" is deferred here.
Phase 2 of the master roadmap is the right home; pairs naturally with
the SaaS pivot (cloud fuzzing infra has the compute budget for AST work
that local regex doesn't need).

**Depends on / blocked by:** Week 4 analyzer MVP. Strong synergy with
`fuzzer.auto-discovery` — implementing one makes the other cheaper.

## analyzer.gitleaks-shim

**What:** Optional integration that detects an installed `gitleaks` (or
`trufflehog`), invokes it under the hood with project-appropriate config,
and merges its findings into the unified Sentinel report after format
conversion + dedup.

**Why:** Sentinel's value is Tauri-specific findings — generic secret
detection is a solved problem owned by gitleaks/trufflehog. Rather than
compete on coverage, integrate. Users get one-pane-of-glass: Tauri
findings from Sentinel + battle-tested generic findings from upstream.

**Pros:**
- Zero maintenance burden on the Sentinel pattern library for generic
  secrets — gitleaks ships ~5000 patterns, kept current upstream.
- TruffleHog's verifier callbacks (live key validation) are uniquely
  valuable and impossible to replicate in regex alone.
- Plays well with security teams already running gitleaks in CI.

**Cons:**
- Adds an external runtime dependency check + invocation surface.
- Format conversion (gitleaks JSON → Sentinel `Finding`) is fiddly.
- User-controlled config path conflicts (a `.gitleaksignore` may want
  to extend Sentinel's `.sentinelignore`, or vice versa).

**Context:** Week 4 ships a small built-in default for the obvious cases
(hardcoded keys with high entropy + ignore-comment respect). The "deep
coverage" story for users with serious secret-detection needs is to
install gitleaks separately, today. This TODO is the upgrade path that
makes that integration ergonomic.

**Depends on / blocked by:** Week 4 analyzer MVP. Independent of
`analyzer.tree-sitter`.

## analyzer.sarif-output

**What:** Emit Sentinel findings in [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
format so the unified report can be consumed by GitHub Code Scanning,
GitLab Vulnerability Reports, and any other CI surface that ingests
SARIF.

**Why:** SARIF is the lingua franca for static-analysis output in 2026.
A SARIF emitter turns Sentinel from "a CLI you run manually" into "a
GitHub Action you `uses:` in your workflow." The deferred GitHub Action
TODO (master roadmap Phase 2) is the natural consumer.

**Pros:**
- One format = many CI integrations: GitHub Advanced Security, GitLab
  SAST, Sonatype, JetBrains, etc. — all consume SARIF.
- Findings show up inline on PRs as code-line annotations, dramatically
  improving DX over "go read this JSON file."
- Standardizes on a public format instead of Sentinel-proprietary JSON
  for tools that want to integrate.

**Cons:**
- SARIF schema is verbose; emitter is ~300 lines of mapping logic.
- Some Sentinel finding fields (`suggestion`, multi-line `description`)
  don't map cleanly to SARIF concepts; lossy in either direction.

**Context:** Week 4 ships JSON + HTML. SARIF is the third format that
unlocks CI ecosystem integration, but it's not on the critical path for
Week 5 MoodBloom dogfooding or the Week 8 launch. Right time is when
the GitHub Action TODO comes due.

**Depends on / blocked by:** Master roadmap Phase 2 (GitHub Action
integration). Independent of the other analyzer TODOs.
