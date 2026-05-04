// Synthetic fuzz target used by the Sentinel integration test suite.
//
// This target deliberately panics on a particular input to verify that
// Sentinel correctly detects, classifies, and reports the crash. The
// integration test does *not* actually run `cargo fuzz` — it feeds Sentinel
// a captured libFuzzer stderr blob (./expected_stderr.txt) that represents
// what libFuzzer would have emitted when this target panicked.
//
// If you change this file, update ./expected_stderr.txt to match.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.starts_with(b"BOOM") {
        panic!("synthetic panic for sentinel integration test");
    }
});
