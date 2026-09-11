//! Unix-socket readiness probing for the tailscaled LocalAPI.

use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::wait_until;

/// Poll cadence for socket readiness.
const TICK: Duration = Duration::from_millis(100);

/// Authoritative readiness check: connect() to the LocalAPI socket (the fd
/// closes on drop). A CLI probe would false-negative on a fresh, logged-out
/// daemon (exit != 0).
fn unix_socket_alive(path: &str) -> bool {
    UnixStream::connect(path).is_ok()
}

/// Poll the LocalAPI socket until tailscaled is listening, or until
/// timeout/abort (`None` covers both; the caller distinguishes the two
/// outcomes via its own stop flag).
pub fn wait_daemon(socket: &str, timeout: Duration, abort: impl Fn() -> bool) -> bool {
    wait_until(
        || unix_socket_alive(socket).then_some(()),
        timeout,
        abort,
        TICK,
    )
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::time::Instant;

    fn sock_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("vw-sup-{name}-{}.sock", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn detects_a_listening_socket() {
        let path = sock_path("live");
        let listener = UnixListener::bind(&path).unwrap();
        assert!(wait_daemon(&path, Duration::from_secs(5), || false));
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn times_out_on_missing_socket() {
        let path = sock_path("absent");
        let start = Instant::now();
        assert!(!wait_daemon(&path, Duration::from_millis(200), || false));
        assert!(start.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn abort_beats_the_timeout() {
        let path = sock_path("abort");
        let start = Instant::now();
        assert!(!wait_daemon(&path, Duration::from_secs(60), || true));
        assert!(start.elapsed() < Duration::from_secs(30));
    }
}
