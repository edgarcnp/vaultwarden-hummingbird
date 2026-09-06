//! Minimal stdout/stderr logging, prefixed for container log scraping.
//!
//! `panic=abort` is set (PID 1 must die loudly, not limp), so a `println!`
//! panic on a closed/broken stdout would take the whole container down.
//! Log writes therefore ignore errors instead of panicking.

use std::io::Write;

/// Log an informational line to stdout. Never panics: a broken stdout
/// (closed pipe, full disk) drops the line instead of killing PID 1.
pub fn info(msg: &str) {
    let _ = writeln!(std::io::stdout().lock(), "[supervisor] {msg}");
}

/// Log an error line to stderr. Never panics (same rationale as [`info`]).
pub fn err(msg: &str) {
    let _ = writeln!(std::io::stderr().lock(), "[supervisor] {msg}");
}
