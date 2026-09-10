//! DB keepalive settings (SUPERVISOR_DB_KEEPALIVE).

use std::time::Duration;

use crate::config::dburl::{self, DbSpec};
use crate::util::log;

/// Issues a trivial query on a cadence so hosts that suspend an idle
/// database (scale-to-zero / auto-stop) stay awake for the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbKeepalive {
    /// the vault's parsed postgres URL — the ping must reach the same DB
    /// the vault uses
    pub db: DbSpec,
    /// ping cadence
    pub interval: Duration,
}

impl DbKeepalive {
    /// Empty/0 = off; non-numeric or non-postgres URL disables (warns only
    /// when the knob was explicitly set — the supervisor speaks only the
    /// postgres wire protocol).
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
        let spec = db_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .and_then(dburl::parse);
        match spec {
            Some(db @ DbSpec::Postgres { .. }) => Some(Self {
                db,
                interval: Duration::from_secs(interval),
            }),
            _ => {
                if explicit {
                    log::err(
                        "config: SUPERVISOR_DB_KEEPALIVE set but VAULTWARDEN_DATABASE_URL is \
                         not a postgres URL; keepalive disabled",
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

    fn pg_spec(db_url: &str) -> DbSpec {
        match dburl::parse(db_url) {
            Some(s @ DbSpec::Postgres { .. }) => s,
            other => panic!("expected a postgres spec, got {other:?}"),
        }
    }

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

        // armed: cadence honored, URL parsed into the spec
        let ka =
            with("300", Some("postgres://u:p@h:5432/db?sslmode=require")).expect("keepalive armed");
        assert_eq!(ka.interval, Duration::from_secs(300));
        assert_eq!(ka.db, pg_spec("postgres://u:p@h:5432/db?sslmode=require"));
        assert!(with("300", Some("postgresql://u:p@h/db")).is_some());

        // whitespace-padded URL is trimmed before parsing
        assert_eq!(
            with("300", Some("  postgres://u:p@h/db  "))
                .expect("armed")
                .db,
            pg_spec("postgres://u:p@h/db")
        );

        // invalid cadence: disabled (warn logged, non-fatal)
        assert!(with("soon", Some("postgres://u:p@h/db")).is_none());
    }
}
