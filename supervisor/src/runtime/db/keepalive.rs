//! DB keepalive ping (opt-in via SUPERVISOR_DB_KEEPALIVE, seconds): a
//! trivial query on a cadence so hosts that suspend an idle database
//! (scale-to-zero) stay awake for the vault. Failures are non-fatal.

use crate::config::{DB_PING_TIMEOUT, DbKeepalive};
use crate::util::log;

use super::pg;

/// One keepalive cycle: fresh connection + `SELECT 1`, bounded by
/// [`DB_PING_TIMEOUT`]. Steady success stays silent (a short cadence would
/// otherwise spam the logs); failures and recoveries log on state change.
pub fn tick(cfg: &DbKeepalive, last_ok: &mut Option<bool>) {
    let ok = ping(&cfg.db);
    if *last_ok != Some(ok) {
        *last_ok = Some(ok);
        if ok {
            log::info("db keepalive: connected");
        } else {
            log::err("db keepalive: ping failed; the vault keeps running");
        }
    }
}

/// Fresh connection + trivial query; nothing is pooled or reused.
fn ping(db: &crate::config::DbSpec) -> bool {
    let Some(mut client) = pg::connect(db, DB_PING_TIMEOUT) else {
        return false;
    };
    client.simple_query("SELECT 1").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn spec() -> crate::config::DbSpec {
        crate::config::DbSpec::Postgres {
            host: Some("127.0.0.1".into()),
            port: 1,
            user: Some("u".into()),
            password: Some("p".into()),
            db: Some("db".into()),
            sslmode: Some("disable".into()),
        }
    }

    /// An unreachable (connection-refused) Postgres must fail fast and
    /// cleanly, not hang the watch loop.
    #[test]
    fn ping_fails_fast_on_refused_connection() {
        assert!(!ping(&spec()));
    }

    /// A non-postgres spec must fail cleanly without panicking.
    #[test]
    fn ping_fails_on_non_postgres_spec() {
        assert!(!ping(&crate::config::DbSpec::Sqlite {
            path: "/nonexistent/db.sqlite3".into()
        }));
    }

    #[test]
    fn tick_tracks_state_across_failures() {
        let cfg = DbKeepalive {
            interval: Duration::from_secs(60),
            db: spec(),
        };
        let mut last = None;
        tick(&cfg, &mut last);
        assert_eq!(last, Some(false));
        tick(&cfg, &mut last);
        assert_eq!(last, Some(false));
    }

    #[test]
    #[ignore = "requires a reachable TLS postgres; covered by deploy"]
    fn tick_logs_recovery() {}
}
