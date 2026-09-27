//! The vault's sqlite database path (`VAULTWARDEN_DATABASE_URL`).
//!
//! The image compiles vaultwarden for sqlite only: an unset URL means
//! vaultwarden's own default (the sqlite DB under `DATA_FOLDER`, pinned to
//! `/data`), `sqlite://<path>` picks an explicit file, a scheme-less value
//! is vaultwarden's sqlite form (the raw string is the file path), and any
//! other scheme fails closed — dumps and restores must reach the same DB
//! the vault uses.
//!
//! `sqlite://` URLs go to diesel, which rewrites the prefix to `file:` and
//! opens with `SQLITE_OPEN_URI` (diesel 2.3.11
//! `sqlite/connection/raw.rs::RawConnection::establish`); SQLite then ends
//! the path at the first `?` (query) or `#` (fragment), percent-decodes
//! `%HH` once, and truncates at a decoded NUL. The supervisor mirrors that
//! exactly, because dumping a path the vault never opens is worse than not
//! dumping at all. Scheme-less values are not URIs and stay verbatim.

/// Parse the sqlite file path out of a database URL. `None` = empty, a
/// foreign scheme (postgres/mysql/...), or a URI path that cannot be a
/// Rust file path (non-UTF-8) — in every case there is no DB to back up.
pub fn sqlite_path(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let path = match raw.split_once("://") {
        Some(("sqlite", rest)) => sqlite_uri_path(rest),
        Some(_) => return None,
        None => raw.to_string(),
    };
    (!path.is_empty()).then_some(path)
}

/// The path SQLite opens for diesel's `file:<rest>` URI: cut at the first
/// `?` or `#`, percent-decode once, truncate at NUL. Malformed escapes are
/// kept literally, as SQLite keeps them.
fn sqlite_uri_path(rest: &str) -> String {
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    let bytes = &rest.as_bytes()[..end];
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            let decoded = hi * 16 + lo;
            if decoded == 0 {
                break; // a decoded NUL truncates the path, like SQLite
            }
            out.push(decoded);
            i += 3;
            continue;
        }
        if b == 0 {
            break;
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The scheme of a database URL (for secret-free logs).
pub fn scheme_for_log(raw: &str) -> String {
    let raw = raw.trim();
    match raw.split_once("://") {
        Some((s, _)) => s.to_string(),
        None => raw.chars().take(32).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_urls_give_the_decoded_uri_path() {
        assert_eq!(
            sqlite_path("sqlite:///data/db.sqlite3").as_deref(),
            Some("/data/db.sqlite3")
        );
        // relative path resolves like the child's working dir
        assert_eq!(
            sqlite_path("sqlite://data/db.sqlite3").as_deref(),
            Some("data/db.sqlite3")
        );
        // diesel opens `file:` + rest with SQLITE_OPEN_URI, so SQLite
        // decodes percent-escapes exactly once
        assert_eq!(
            sqlite_path("sqlite:///data/my%20db.sqlite3").as_deref(),
            Some("/data/my db.sqlite3")
        );
        assert_eq!(
            sqlite_path("sqlite:///data/pct%2520.db").as_deref(),
            Some("/data/pct%20.db")
        );
        assert_eq!(
            sqlite_path("sqlite:///data/plus+name.db").as_deref(),
            Some("/data/plus+name.db")
        );
        // the query and fragment parts are not part of the path
        assert_eq!(
            sqlite_path("sqlite:///data/db.sqlite3?mode=ro").as_deref(),
            Some("/data/db.sqlite3")
        );
        assert_eq!(
            sqlite_path("sqlite:///data/db.sqlite3#frag").as_deref(),
            Some("/data/db.sqlite3")
        );
        // malformed escapes are kept literally (as SQLite keeps them)
        assert_eq!(
            sqlite_path("sqlite:///data/pct%ZZ.db").as_deref(),
            Some("/data/pct%ZZ.db")
        );
        assert_eq!(
            sqlite_path("sqlite:///data/trail%.db").as_deref(),
            Some("/data/trail%.db")
        );
        // a decoded NUL truncates the path
        assert_eq!(
            sqlite_path("sqlite:///data/a%00b.db").as_deref(),
            Some("/data/a")
        );
        // a bare scheme names an empty path: nothing to back up
        assert_eq!(sqlite_path("sqlite://"), None);
        // surrounding whitespace is not part of the path
        assert_eq!(
            sqlite_path("  sqlite:///data/db.sqlite3  ").as_deref(),
            Some("/data/db.sqlite3")
        );
    }

    #[test]
    fn scheme_less_values_are_the_vaults_sqlite_form() {
        assert_eq!(
            sqlite_path("/data/db.sqlite3").as_deref(),
            Some("/data/db.sqlite3")
        );
        assert_eq!(
            sqlite_path("data/db.sqlite3").as_deref(),
            Some("data/db.sqlite3")
        );
        // no `file:` prefix means no URI decoding (verified against sqlite3)
        assert_eq!(
            sqlite_path("data/my%20db.sqlite3").as_deref(),
            Some("data/my%20db.sqlite3")
        );
    }

    #[test]
    fn foreign_schemes_and_empty_are_rejected() {
        assert_eq!(sqlite_path(""), None);
        assert_eq!(sqlite_path("   "), None);
        assert_eq!(sqlite_path("postgres://u:p@h/db"), None);
        assert_eq!(sqlite_path("postgresql://u:p@h/db"), None);
        assert_eq!(sqlite_path("mysql://u:p@h/db"), None);
        assert_eq!(sqlite_path("oracle://u:p@h/db"), None);
    }

    #[test]
    fn scheme_for_log_never_carries_secrets() {
        assert_eq!(scheme_for_log("postgres://u:p@h/db"), "postgres");
        assert_eq!(scheme_for_log("  sqlite:///data/db  "), "sqlite");
        assert_eq!(scheme_for_log("garbage"), "garbage");
        assert_eq!(scheme_for_log("no-secret-here://x"), "no-secret-here");
    }
}
