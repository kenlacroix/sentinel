// Synthetic-vuln fixture: deliberately contains intentional security issues
// the Sentinel analyzer must detect. This file is never compiled — the
// integration test runs Sentinel against the source on disk.
//
// Issues seeded here, with expected rule_id:
//
//   - command-injection sink reachable from a tauri command   tauri.command_injection
//   - path-traversal sink reachable from a tauri command      tauri.path_traversal
//   - unsafe block inside a tauri command body                tauri.unsafe_in_command
//   - weak hash (Md5) used in a security context              crypto.weak_hash
//
// Adding or removing issues here REQUIRES updating tests/end_to_end.rs.

use std::process::Command;

#[tauri::command]
fn run_user_command(input: String) {
    let _ = Command::new(&input).spawn();
}

#[tauri::command]
fn read_user_file(path: String) {
    let _ = std::fs::read_to_string(&path);
}

#[tauri::command]
fn unsafe_handler(data: Vec<u8>) {
    unsafe {
        let _ = std::ptr::read(data.as_ptr());
    }
}

fn hash_token(token: &[u8]) -> String {
    let digest = Md5::new();
    let _ = digest;
    let _ = token;
    String::new()
}
