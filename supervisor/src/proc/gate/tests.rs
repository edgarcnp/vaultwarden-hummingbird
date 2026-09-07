//! Gatekeeper server tests: request handling, exposure verdicts, bounds.

use std::net::{Shutdown, SocketAddr};
use std::time::{Duration, Instant};

use super::probe::fake_vault;
use super::{bind, handle};

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
    std::io::Write::write_all(&mut c, request).unwrap();
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
        let start = Instant::now();
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
