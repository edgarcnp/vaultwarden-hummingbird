//! Minimal stdout/stderr logging, prefixed for container log scraping.
//! Log writes ignore errors instead of panicking: `panic=abort` means a
//! `println!` panic on a broken stdout would take PID 1 (and the container)
//! down with it.

use std::io::Write;

/// Log an informational line to stdout (never panics; a broken stdout drops
/// the line instead of killing PID 1).
pub fn info(msg: &str) {
    let _ = writeln!(std::io::stdout().lock(), "[supervisor] {msg}");
}

/// Log an error line to stderr (never panics, same rationale as [`info`]).
pub fn err(msg: &str) {
    let _ = writeln!(std::io::stderr().lock(), "[supervisor] {msg}");
}

/// Escape untrusted values before logging via std's [`str::escape_debug`]:
/// newlines, tabs, control characters, quotes, and backslashes are turned
/// into their escaped form, so user input can never forge additional log
/// lines.
pub fn sanitize(s: &str) -> String {
    s.escape_debug().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(sanitize("plain"), "plain");
        assert_eq!(sanitize("a\nb"), "a\\nb");
        assert_eq!(sanitize("a\r\nb"), "a\\r\\nb");
        assert_eq!(sanitize("a\tb"), "a\\tb");
        assert_eq!(sanitize("\u{7}"), "\\u{7}");
    }
}
