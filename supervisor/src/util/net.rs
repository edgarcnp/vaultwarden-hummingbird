//! Unix-socket readiness probing for the tailscaled LocalAPI. A probe is a
//! `connect`, not a CLI call, so a fresh logged-out daemon still counts as up.

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use super::wait_until;
use crate::util::log;

/// Poll cadence for socket readiness.
const TICK: Duration = Duration::from_millis(100);

/// Authoritative readiness check: connect() to the LocalAPI socket (the fd
/// closes on drop). A CLI probe would false-negative on a fresh, logged-out
/// daemon (exit != 0).
fn unix_socket_alive(path: &str) -> bool {
    UnixStream::connect(path).is_ok()
}

/// Poll until tailscaled listens, the timeout passes, or `abort` fires,
/// returning false for the last two; the caller's stop flag distinguishes them.
/// The connect runs detached so a full listen backlog cannot outlive the wait.
pub fn wait_daemon(socket: &str, timeout: Duration, abort: impl Fn() -> bool) -> bool {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let path = socket.to_string();
    let worker = std::thread::Builder::new()
        .name("daemon-wait".into())
        .spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                if unix_socket_alive(&path) {
                    let _ = tx.send(());
                    return;
                }
                std::thread::sleep(TICK);
            }
        });
    if let Err(e) = worker {
        log::err(&format!(
            "cannot start the daemon-wait worker ({e}); reporting the socket as not ready"
        ));
        return false;
    }
    let ready = wait_until(|| rx.try_recv().ok(), timeout, abort, TICK);
    stop.store(true, Ordering::Relaxed);
    ready.is_some()
}

#[cfg(test)]
mod tests {
    //! Readiness tests over real Unix sockets.

    use super::*;
    use std::os::unix::net::UnixListener;
    use std::time::Instant;

    /// A unique per-test socket path under the temp dir.
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
