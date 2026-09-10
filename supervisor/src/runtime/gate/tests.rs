//! Gatekeeper server tests: request handling, exposure verdicts, bounds.

use std::net::{Shutdown, SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::liveness::Liveness;
use super::probe::fake_vault;
use super::server::{bind, handle, serve_with};

/// A vaultwarden stand-in that answers 200 forever and counts requests
/// (the TTL-window and admission tests need to observe probe fan-out).
fn counting_vault() -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = l.local_addr().unwrap();
    let hits_counter = Arc::clone(&hits);
    std::thread::spawn(move || {
        for mut conn in l.incoming().flatten() {
            hits_counter.fetch_add(1, Ordering::Relaxed);
            let mut req = [0u8; 512];
            let _ = std::io::Read::read(&mut conn, &mut req);
            let _ = std::io::Write::write_all(
                &mut conn,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    (addr, hits)
}

/// Ephemeral listener + one request -> full response (read to EOF).
/// `vault = None` doubles as a probe canary: if `/alive` ever reached
/// the probe with it, the answer would be 503, not what these tests
/// expect from the 403 paths.
fn roundtrip(request: &[u8], vault: Option<SocketAddr>) -> String {
    let listener = bind("0").expect("ephemeral bind");
    let addr = listener.local_addr().unwrap();
    let live = Arc::new(Liveness::new(vault));
    let t = std::thread::spawn(move || {
        let s = listener.incoming().next().unwrap().unwrap();
        handle(s, &live);
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
        // absolute-form (RFC 7230 §5.3.2): proxied clients send this
        b"GET http://0.0.0.0:8080/alive HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET https://host.tailnet.ts.net/alive?probe=1 HTTP/1.1\r\n\r\n",
    ] {
        // fresh one-shot vault per request (the helper serves exactly one)
        let resp = roundtrip(req, Some(fake_vault("200 OK")));
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{req:?} -> {resp}");
    }
}

/// Only GET /alive is the liveness probe: other methods are refused
/// without touching the vault (protocol strictness; a POST that mutated
/// state must never read as "healthy").
#[test]
fn non_get_methods_answer_403() {
    for req in [
        &b"HEAD /alive HTTP/1.1\r\n\r\n"[..],
        b"POST /alive HTTP/1.1\r\n\r\n",
        b"DELETE /alive HTTP/1.1\r\n\r\n",
        b"OPTIONS /alive HTTP/1.1\r\n\r\n",
        b"get /alive HTTP/1.1\r\n\r\n",
    ] {
        let resp = roundtrip(req, None);
        assert!(
            resp.starts_with("HTTP/1.1 403 Forbidden\r\n"),
            "{req:?} -> {resp}"
        );
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
        handle(s, &Liveness::new(None));
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

/// Concurrent /alive requests each get a verdict (thread-safety under
/// load); the admission cap in `server` bounds how many can probe at once,
/// and the TTL window amortizes a steady flood to one probe per window
/// (covered by `liveness_verdict_expires_with_the_window`).
#[test]
fn concurrent_alive_requests_all_get_a_verdict() {
    let (vault, _hits) = counting_vault();
    let live = Arc::new(Liveness::with_ttl(Some(vault), Duration::from_secs(10)));
    let verdicts: Vec<_> = (0..8)
        .map(|_| {
            let live = Arc::clone(&live);
            std::thread::spawn(move || live.alive())
        })
        .collect();
    for v in verdicts {
        assert!(v.join().unwrap(), "counting vault always answers 200");
    }
}

/// A verdict is shared only within its TTL window; after expiry the next
/// request probes again.
#[test]
fn liveness_verdict_expires_with_the_window() {
    let (vault, hits) = counting_vault();
    let live = Liveness::with_ttl(Some(vault), Duration::from_millis(50));
    assert!(live.alive());
    assert!(live.alive(), "fresh within the window");
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    std::thread::sleep(Duration::from_millis(150));
    assert!(live.alive(), "expired window reprobes");
    assert_eq!(hits.load(Ordering::Relaxed), 2);
}

/// Admission cap: connections beyond the cap get an immediate 503 (no
/// thread, no backend probe), and a released slot is served again.
#[test]
fn admission_bounds_concurrent_handlers() {
    let (vault, hits) = counting_vault();
    let listener = bind("0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(std::thread::spawn(move || {
        serve_with(listener, Some(vault), 1)
    }));

    let get = |request: &[u8]| {
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        std::io::Write::write_all(&mut c, request).unwrap();
        let mut resp = String::new();
        let _ = std::io::Read::read_to_string(&mut c, &mut resp);
        resp
    };

    // Holder: connected but silent — occupies the one handler slot.
    let holder = std::net::TcpStream::connect(addr).unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // Over limit: immediate 503. (Had it been admitted, the counting
    // vault would have answered 200.)
    let resp = get(b"GET /alive HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(
        resp.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "over-limit conn must be rejected: {resp}"
    );
    assert_eq!(hits.load(Ordering::Relaxed), 0, "reject never probes");

    // Release the slot; the next request is admitted and served.
    drop(holder);
    std::thread::sleep(Duration::from_millis(200));
    let resp = get(b"GET /alive HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(
        resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "released slot serves again: {resp}"
    );
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}
