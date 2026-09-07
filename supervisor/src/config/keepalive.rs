//! DB keepalive settings (opt-in via SUPERVISOR_DB_KEEPALIVE): the
//! [`DbKeepalive`] carried by `Config` and consumed by
//! `crate::proc::keepalive`, the runner.

use std::time::Duration;

use crate::util::log;

/// DB keepalive: issues a trivial query on a cadence so hosts that suspend
/// an idle database (scale-to-zero / auto-stop) stay awake for the vault.
/// Opt-in via SUPERVISOR_DB_KEEPALIVE (seconds; unset = off, 0 = off).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbKeepalive {
    /// vaultwarden's DATABASE_URL — the ping must reach the same DB the
    /// vault uses; never logged (carries credentials)
    pub url: String,
    /// ping cadence
    pub interval: Duration,
}

impl DbKeepalive {
    /// Empty/0 = off; non-numeric warns and disables; a non-postgres URL
    /// disables (warns only when the knob was explicitly set) — the
    /// supervisor speaks only the postgres wire protocol.
    pub fn from_parts(raw: &str, db_url: Option<String>) -> Option<Self> {
        let explicit = !raw.is_empty();
        let interval = match raw.parse::<u64>() {
            Ok(0) => return None,
            Ok(secs) => secs,
            Err(_) => {
                if explicit {
                    log::err(&format!(
                        "config: invalid SUPERVISOR_DB_KEEPALIVE '{}' (want seconds); \
                         keepalive disabled",
                        log::sanitize(raw)
                    ));
                }
                return None;
            }
        };
        match db_url.as_deref().map(str::trim) {
            Some(u) if u.starts_with("postgres://") || u.starts_with("postgresql://") => {
                Some(Self {
                    url: u.to_string(),
                    interval: Duration::from_secs(interval),
                })
            }
            _ => {
                if explicit {
                    log::err(
                        "config: SUPERVISOR_DB_KEEPALIVE set but DATABASE_URL is not a \
                         postgres URL; keepalive disabled",
                    );
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keepalive resolution: off by default, cadence knob drives it, and it
    /// only arms when the vault's DB is a postgres URL (the supervisor's
    /// ping speaks the postgres wire protocol).
    #[test]
    fn db_keepalive_resolution() {
        fn with(raw: &str, db: Option<&str>) -> Option<DbKeepalive> {
            DbKeepalive::from_parts(raw, db.map(String::from))
        }

        // unset knob / empty / explicit 0: off regardless of DB
        assert!(with("", Some("postgres://u:p@h/db")).is_none());
        assert!(with("0", Some("postgres://u:p@h/db")).is_none());
        assert!(with("", None).is_none());

        // knob without a DB url: disabled, no phantom keepalive
        assert!(with("300", None).is_none());

        // non-postgres DB (sqlite/mysql) can't be pinged by the supervisor
        assert!(with("300", Some("sqlite:///data/db.sqlite3")).is_none());
        assert!(with("300", Some("mysql://u:p@h/db")).is_none());

        // armed: cadence honored, URL carried verbatim
        let ka =
            with("300", Some("postgres://u:p@h:5432/db?sslmode=require")).expect("keepalive armed");
        assert_eq!(ka.interval, Duration::from_secs(300));
        assert_eq!(ka.url, "postgres://u:p@h:5432/db?sslmode=require");
        assert!(with("300", Some("postgresql://u:p@h/db")).is_some());

        // whitespace-padded URL is trimmed
        assert_eq!(
            with("300", Some("  postgres://u:p@h/db  "))
                .expect("armed")
                .url,
            "postgres://u:p@h/db"
        );

        // invalid cadence: disabled (warn logged, non-fatal)
        assert!(with("soon", Some("postgres://u:p@h/db")).is_none());
    }
}
