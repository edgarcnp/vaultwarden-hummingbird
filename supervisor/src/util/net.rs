//! Unix-socket readiness probing for the tailscaled LocalAPI.

use std::ffi::CString;
use std::time::{Duration, Instant};

/// Authoritative readiness check: can we connect() to the LocalAPI socket?
/// std has no UnixSocket, so this goes through libc directly. A CLI probe
/// would false-negative on a fresh, logged-out daemon (exit != 0).
fn unix_socket_alive(path: &str) -> bool {
    let c = match CString::new(path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return false;
        }
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = c.as_bytes_with_nul();
        if bytes.len() > addr.sun_path.len() {
            libc::close(fd);
            return false;
        }
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        let ret = libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        );
        libc::close(fd);
        ret == 0
    }
}

/// Poll the LocalAPI socket until tailscaled is listening (or timeout).
/// `abort` is checked each tick so a stop request never waits out the wait
/// (the caller distinguishes the two outcomes itself).
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
