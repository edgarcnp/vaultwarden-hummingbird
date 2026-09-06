//! Minimal stdout/stderr logging, prefixed for container log scraping.

/// Log an informational line to stdout.
pub fn info(msg: &str) {
    println!("[supervisor] {msg}");
}

/// Log an error line to stderr.
pub fn err(msg: &str) {
    eprintln!("[supervisor] {msg}");
}
