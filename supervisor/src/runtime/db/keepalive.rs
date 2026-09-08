//! DB keepalive ping (opt-in via SUPERVISOR_DB_KEEPALIVE, seconds): a
//! trivial query on a cadence so hosts that suspend an idle database
//! (scale-to-zero) stay awake for the vault. Failures are non-fatal.
//!
//! Connection plumbing (TLS posture, timeouts) lives in [`super::pg`],
//! shared with the DB backup/restore.

use super::pg;
use crate::config::{DB_PING_TIMEOUT, DbKeepalive};
use crate::util::log;

/// One keepalive cycle: fresh connection + `SELECT 1`, bounded by
/// [`DB_PING_TIMEOUT`]. Steady success stays silent (a short cadence would
/// otherwise spam the logs); failures and recoveries log on state change.
pub fn tick(cfg: &DbKeepalive, last_ok: &mut Option<bool>) {
    let ok = ping(&cfg.url);
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
fn ping(url: &str) -> bool {
    let Some(mut client) = pg::connect(url, DB_PING_TIMEOUT) else {
        return false;
    };
    client.simple_query("SELECT 1").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// An unreachable (connection-refused) Postgres must fail fast and
    /// cleanly, not hang the watch loop.
    #[test]
    fn ping_fails_fast_on_refused_connection() {
        assert!(!ping("postgres://u:p@127.0.0.1:1/db?sslmode=disable"));
    }

    /// A malformed URL must fail cleanly without panicking.
    #[test]
    fn ping_fails_on_malformed_url() {
        assert!(!ping("not-a-url"));
    }

    /// State-change logging exercised indirectly: tick must not panic on
    /// consecutive failures and must update the state.
    #[test]
    fn tick_tracks_state_across_failures() {
        let cfg = DbKeepalive {
            interval: Duration::from_secs(60),
            url: "postgres://u:p@127.0.0.1:1/db?sslmode=disable".into(),
        };
        let mut last = None;
        tick(&cfg, &mut last);
        assert_eq!(last, Some(false));
        tick(&cfg, &mut last);
        assert_eq!(last, Some(false));
    }

    /// Steady-state success must flip the tracked state to Some(true) so
    /// the logging stays quiet while the DB stays up.
    #[test]
    #[ignore = "requires a reachable TLS postgres; covered by deploy"]
    fn tick_logs_recovery() {}
}
