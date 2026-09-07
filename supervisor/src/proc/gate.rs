//! Exposed-port gatekeeper: the only listener on the container's public
//! port. It makes the exposure model explicit — the Bitwarden API lives on a
//! loopback-only port that only `tailscale serve` can reach, while this
//! listener reports vault liveness and refuses everything else.
//!
//! std-only (no HTTP crate); the surface is deliberately two responses wide:
//! `200 OK` for requests targeting `/alive` (method- and query-agnostic —
//! only the path is examined) *iff* vaultwarden's own `/alive` answers 2xx
//! on the loopback port, `503 Service Unavailable` when it does not, and
//! `403 Forbidden` for every other request. The probe result is reduced to
//! a bare status: vaultwarden's response body and headers are discarded
//! (nothing of the vault's internals travels out through the gate), and
//! denied requests are not logged (platform health probes and drive-by
//! scanners would otherwise dominate the container log). Every path is
//! bounded: read/probe timeouts, capped request size, `Connection: close`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use crate::util::log;

/// One bounded read buffer for the request head; anything past this is
/// noise — the decision only needs the first line.
const REQ_CAP: usize = 2048;
/// No request may hold a gatekeeper thread for longer than this.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard budget for one vaultwarden liveness probe (connect + status line).
/// Under the gate's own [`READ_TIMEOUT`] so the probe can never be the
/// reason a health check times out.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Probe result when vaultwarden does not answer 2xx (down, hung, or the
/// probe failed): health checks must see the vault, not just the container.
const VAULT_DOWN: (&str, &str) = ("503", "Service Unavailable");

/// Bind the exposed port on `0.0.0.0`. Failure here means the deployment
/// itself is broken (health checks unreachable), so the caller exits rather
/// than running a vault nobody can probe. An unparseable port is a bind
/// error, never a silent ephemeral fallback.
pub fn bind(port: &str) -> std::io::Result<TcpListener> {
    let port: u16 = port
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid port"))?;
    TcpListener::bind(("0.0.0.0", port))
}

/// Serve the bound listener forever, probing vaultwarden at `vault`
/// (loopback socket addr) for `/alive`. Detached-thread contract: the
/// container's lifetime is the listener's lifetime; shutdown closes the
/// process, not the loop. One thread per connection (probes are rare;
/// thread lifetime is capped by [`READ_TIMEOUT`]).
pub fn serve(listener: TcpListener, vault: Option<std::net::SocketAddr>) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => drop(std::thread::spawn(move || handle(s, vault))),
            Err(_) => continue,
        }
    }
}

/// Boot-time log line describing the exposure model (single line, no secrets).
pub fn describe(exposed: &str, vault: &str) {
    log::info(&format!(
        "gatekeeper: /alive on 0.0.0.0:{exposed}; API loopback-only on 127.0.0.1:{vault} \
         (tailnet via tailscale serve)"
    ));
}

/// One request, one response, connection closed. Only the first line of the
/// request head is inspected (`METHOD /path HTTP/x.y`); a malformed,
/// truncated, or oversized request is just another denied request — the
/// probe (and thus vaultwarden) is never touched by non-`/alive` traffic. A
/// read error (timeout, reset) closes the connection without a response —
/// there is nothing to answer.
fn handle(mut stream: TcpStream, vault: Option<std::net::SocketAddr>) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let mut buf = [0u8; REQ_CAP];
    let mut used = 0;
    let line = loop {
        if let Some(pos) = buf[..used].iter().position(|&b| b == b'\n') {
            break line_of(&buf[..pos]);
        }
        if used == buf.len() {
            break String::new();
        }
        match stream.read(&mut buf[used..]) {
            Ok(0) => break line_of(&buf[..used]),
            Ok(n) => used += n,
            Err(_) => return,
        }
    };
    let alive = line
        .split_whitespace()
        .nth(1)
        .map(target_path)
        .and_then(|target| target.split('?').next())
        .is_some_and(|path| path == "/alive");
    let (code, text) = if !alive {
        ("403", "Forbidden")
    } else if probe_vault(vault) {
        ("200", "OK")
    } else {
        VAULT_DOWN
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {code} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
}

/// Bounded liveness probe of vaultwarden's own `/alive`: connect, send one
/// request, read only the status line. Any failure — unreachable, hung
/// ([`PROBE_TIMEOUT`]), non-HTTP, non-2xx — is a plain `false`; the caller
/// answers `503`. Nothing from the vault's response (body, headers, timing
/// details) beyond the status verdict reaches the gate's answer.
fn probe_vault(vault: Option<std::net::SocketAddr>) -> bool {
    let Some(addr) = vault else {
        return false;
    };
    let Ok(mut s) = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(PROBE_TIMEOUT));
    let _ = s.set_write_timeout(Some(PROBE_TIMEOUT));
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

/// First request line as trimmed UTF-8 (empty on undecodable input).
fn line_of(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes)
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// The request target's path per RFC 7230 §5.3: origin-form `/path?query`
/// passes through (minus query); absolute-form
/// `scheme://authority/path?query` (proxied clients) contributes the part
/// after the authority. Authority-form and asterisk-form never match
/// `/alive`; anything unparseable denies the request.
fn target_path(target: &str) -> &str {
    let rest = match target.split_once("://") {
        Some((_, r)) => r,
        None => return target,
    };
    match rest.find('/') {
        Some(i) => &rest[i..],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{Shutdown, SocketAddr};
    use std::time::Duration;

    /// A stand-in vaultwarden: one-shot listener answering `status`.
    fn fake_vault(status: &'static str) -> SocketAddr {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut req = [0u8; 512];
                let _ = std::io::Read::read(&mut c, &mut req);
                let _ = c.write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                );
            }
        });
        addr
    }

    /// Ephemeral listener + one request -> full response (read to EOF).
    /// `vault = None` doubles as a probe canary: if `/alive` ever reached
    /// the probe with it, the answer would be 503, not what these tests
    /// expect from the 403 paths.
    fn roundtrip(request: &[u8], vault: Option<SocketAddr>) -> String {
        let listener = bind("0").expect("ephemeral bind");
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let s = listener.incoming().next().unwrap().unwrap();
            handle(s, vault);
        });
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.write_all(request).unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut resp = String::new();
        let _ = std::io::Read::read_to_string(&mut c, &mut resp);
        t.join().unwrap();
        resp
    }

    #[test]
    fn alive_answers_200_when_vault_is_healthy() {
        let vault = fake_vault("200 OK");
        let resp = roundtrip(b"GET /alive HTTP/1.1\r\nHost: x\r\n\r\n", Some(vault));
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.contains("Connection: close"), "{resp}");
        assert!(
            !resp.contains("Content-Length: 0\r\n\r\n"),
            "bare status only"
        );
    }

    #[test]
    fn alive_answers_503_when_vault_is_down_or_unhealthy() {
        for vault in [None, Some(fake_vault("500 Internal Server Error"))] {
            let resp = roundtrip(b"GET /alive HTTP/1.1\r\n\r\n", vault);
            assert!(
                resp.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
                "{vault:?} -> {resp}"
            );
        }
    }

    /// The gate forwards only a status verdict: nothing of the vault's
    /// response (headers, JSON body with its timestamp) may leak through.
    #[test]
    fn vault_response_never_leaks_through_the_gate() {
        let vault = fake_vault("200 OK");
        let resp = roundtrip(b"GET /alive HTTP/1.1\r\n\r\n", Some(vault));
        assert_eq!(
            resp,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn alive_variants_answer_200() {
        for req in [
            &b"GET /alive?probe=1 HTTP/1.1\r\n\r\n"[..],
            b"HEAD /alive HTTP/1.1\r\n\r\n",
            b"POST /alive HTTP/1.1\r\n\r\n", // method-agnostic by design
            // absolute-form (RFC 7230 §5.3.2): proxied clients send this
            b"GET http://0.0.0.0:8080/alive HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET https://host.tailnet.ts.net/alive?probe=1 HTTP/1.1\r\n\r\n",
        ] {
            // fresh one-shot vault per request (the helper serves exactly one)
            let resp = roundtrip(req, Some(fake_vault("200 OK")));
            assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{req:?} -> {resp}");
        }
    }

    /// Absolute-form targets whose *path* is not /alive stay denied even
    /// when the authority contains "alive" somewhere.
    #[test]
    fn absolute_form_is_matched_on_path_not_authority() {
        for req in [
            &b"GET http://alive.example.com/ HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            b"GET http://host:8080/aliveat HTTP/1.1\r\n\r\n",
            b"OPTIONS * HTTP/1.1\r\n\r\n",
            b"CONNECT host:443 HTTP/1.1\r\n\r\n",
        ] {
            let resp = roundtrip(req, None);
            assert!(
                resp.starts_with("HTTP/1.1 403 Forbidden\r\n"),
                "{req:?} -> {resp}"
            );
        }
    }

    #[test]
    fn api_paths_answer_403() {
        for req in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            b"GET /api/accounts/prelogin HTTP/1.1\r\n\r\n",
            b"GET /alive/../api HTTP/1.1\r\n\r\n",
            b"GET /alivex HTTP/1.1\r\n\r\n",
            b"GET /alive/ HTTP/1.1\r\n\r\n",
        ] {
            let resp = roundtrip(req, None);
            assert!(
                resp.starts_with("HTTP/1.1 403 Forbidden\r\n"),
                "{req:?} -> {resp}"
            );
        }
    }

    #[test]
    fn malformed_or_empty_requests_answer_403() {
        for req in [&b""[..], b"not-a-request", b"\xff\xfe garbage"] {
            let resp = roundtrip(req, None);
            assert!(
                resp.starts_with("HTTP/1.1 403 Forbidden\r\n"),
                "{req:?} -> {resp}"
            );
        }
    }

    /// Requests that never finish must not hold a gatekeeper thread forever.
    #[test]
    fn silent_connections_are_bounded_by_read_timeout() {
        let listener = bind("0").expect("ephemeral bind");
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let s = listener.incoming().next().unwrap().unwrap();
            let start = std::time::Instant::now();
            handle(s, None);
            start.elapsed() < Duration::from_secs(30)
        });
        let _c = std::net::TcpStream::connect(addr).unwrap();
        assert!(t.join().unwrap(), "handle() did not return within 30s");
    }

    /// The gate must not double-bind a port already in use.
    #[test]
    fn bind_conflict_is_an_error() {
        let listener = bind("0").expect("ephemeral bind");
        let port = listener.local_addr().unwrap().port();
        assert!(bind(&port.to_string()).is_err());
    }
}
