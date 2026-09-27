//! Unix-socket readiness probing for the tailscaled LocalAPI.

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
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
///
/// The blocking connect runs on a detached worker, and the caller waits on
/// its verdict: a full listen backlog makes `connect()` block, and without
/// the separation that single call could outlive the timeout. The worker
/// checks the stop flag between attempts, so it exits (at the latest after
/// one blocked connect returns) once the caller has given up.
pub fn wait_daemon(socket: &str, timeout: Duration, abort: impl Fn() -> bool) -> bool {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let path = socket.to_string();
    drop(std::thread::spawn(move || {
        while !worker_stop.load(Ordering::Relaxed) {
            if unix_socket_alive(&path) {
                let _ = tx.send(());
                return;
            }
            std::thread::sleep(TICK);
        }
    }));
    let ready = wait_until(|| rx.try_recv().ok(), timeout, abort, TICK);
    stop.store(true, Ordering::Relaxed);
    ready.is_some()
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
