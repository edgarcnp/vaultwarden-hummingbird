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

/// Escape control characters in untrusted values before logging: a newline
/// in user input (env var, .env value) must not forge additional log lines.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
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
