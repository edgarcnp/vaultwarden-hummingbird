//! Unix-socket readiness probing for the tailscaled LocalAPI.

use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// Authoritative readiness check: connect() to the LocalAPI socket (the fd
/// closes on drop). A CLI probe would false-negative on a fresh, logged-out
/// daemon (exit != 0).
fn unix_socket_alive(path: &str) -> bool {
    UnixStream::connect(path).is_ok()
}

/// Poll the LocalAPI socket until tailscaled is listening, or until
/// timeout/abort (`abort` is checked each tick so a stop request never
/// waits out the wait; the caller distinguishes the two outcomes).
pub fn wait_daemon(socket: &str, timeout: Duration, abort: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if unix_socket_alive(socket) {
            return true;
        }
        if abort() || Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

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
