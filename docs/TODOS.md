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
