//! One bounded HTTP roundtrip to vaultwarden's loopback `/alive`: the
//! status verdict shared byte-identically by the gate's per-request probe
//! and the one-shot healthcheck. Nothing from the response (body, headers,
//! timing) beyond the verdict escapes this module.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Hard budget for one vaultwarden liveness probe (connect + status line),
/// under the gate's own read timeout so the probe can never be the reason
/// a health check times out.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Connect, send one request, read only the status line, report whether it
/// is 2xx. Any failure — unreachable, hung, non-HTTP, non-2xx — is a plain
/// `false`.
pub fn get_alive(addr: std::net::SocketAddr, timeout: Duration) -> bool {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(timeout));
    let _ = s.set_write_timeout(Some(timeout));
    if s.write_all(b"GET /alive HTTP/1.1\r\nHost: vault\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 1024];
    let mut used = 0;
    let line = loop {
        if let Some(pos) = buf[..used].iter().position(|&b| b == b'\n') {
            break &buf[..pos];
        }
        if used == buf.len() {
            return false;
        }
        match s.read(&mut buf[used..]) {
            Ok(0) => break &buf[..used],
            Ok(n) => used += n,
            Err(_) => return false,
        }
    };
    std::str::from_utf8(line)
        .ok()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .is_some_and(|c| (200..300).contains(&c))
}

/// A stand-in vaultwarden: one-shot listener answering `status`.
#[cfg(test)]
pub fn fake_vault(status: &'static str) -> std::net::SocketAddr {
    use std::net::TcpListener;

    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let mut req = [0u8; 512];
            let _ = std::io::Read::read(&mut c, &mut req);
            let _ = std::io::Write::write_all(
                &mut c,
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            );
        }
    });
    addr
}
