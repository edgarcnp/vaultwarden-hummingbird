//! The vault's sqlite database path (`VAULTWARDEN_DATABASE_URL`).
//!
//! The image compiles vaultwarden for sqlite only: an unset URL means
//! vaultwarden's own default (the sqlite DB under `DATA_FOLDER`, pinned to
//! `/data`), `sqlite://<path>` picks an explicit file, a scheme-less value
//! is vaultwarden's sqlite form (the raw string is the file path), and any
//! other scheme fails closed — dumps and restores must reach the same DB
//! the vault uses.

use percent_encoding::percent_decode_str;

/// Parse the sqlite file path out of a database URL. `None` = empty or a
/// foreign scheme (postgres/mysql/...) the pinned vault cannot use.
pub fn sqlite_path(raw: &str) -> Option<String> {
    let raw = raw.trim();
    match raw.split_once("://") {
        Some(("sqlite", rest)) => Some(percent_decode_str(rest).decode_utf8_lossy().into_owned()),
        Some(_) => None,
        None if raw.is_empty() => None,
        None => Some(raw.to_string()),
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
    fn sqlite_urls_give_the_path() {
        assert_eq!(
            sqlite_path("sqlite:///data/db.sqlite3").as_deref(),
            Some("/data/db.sqlite3")
        );
        // relative path resolves like the child's working dir
        assert_eq!(
            sqlite_path("sqlite://data/db.sqlite3").as_deref(),
            Some("data/db.sqlite3")
        );
        // percent-escaped path components are decoded
        assert_eq!(
            sqlite_path("sqlite:///data/my%20db.sqlite3").as_deref(),
            Some("/data/my db.sqlite3")
        );
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
