//! The exposure server: bind the public port, answer `/alive` with the
//! vault's verdict, refuse everything else. std-only (no HTTP crate); the
//! surface is deliberately two responses wide. Denied requests are not
//! logged (platform health probes and drive-by scanners would otherwise
//! dominate the container log). Every path is bounded: read/probe timeouts,
//! capped request size, `Connection: close`.
//!
//! The port is public, so load is adversarial: handler threads are
//! admitted up to a cap and excess connections get an immediate 503 (no
//! queue, no thread growth), and `/alive` verdicts are TTL-cached (see
//! `limiter`, `liveness` for the flood math).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::limiter::Limiter;
use super::liveness::Liveness;

use crate::util::log;

/// One bounded read buffer for the request head; the decision only needs
/// the first line.
const REQ_CAP: usize = 2048;
/// No request may hold a gatekeeper thread for longer than this.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Probe result when vaultwarden does not answer 2xx: health checks must
/// see the vault, not just the container.
const VAULT_DOWN: (&str, &str) = ("503", "Service Unavailable");
/// Handler threads admitted at once. The container healthcheck plus a
/// platform's redundant probes fit with room to spare; anything beyond is
/// flood, and flood gets 503.
const MAX_CONNS: usize = 32;

/// Pause after an accept error that means descriptor exhaustion; without
/// it the listener stays readable and the loop spins.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Bind the exposed port on `0.0.0.0`. Failure means the deployment is
/// broken (health checks unreachable); the caller exits. An unparseable
/// port is a bind error, never a silent ephemeral fallback.
pub fn bind(port: &str) -> std::io::Result<TcpListener> {
    let port: u16 = port
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid port"))?;
    TcpListener::bind(("0.0.0.0", port))
}

/// Serve the bound listener forever, probing vaultwarden at `vault` for
/// `/alive`. Detached-thread contract: the container's lifetime is the
/// listener's lifetime; shutdown closes the process, not the loop.
pub fn serve(listener: TcpListener, vault: Option<std::net::SocketAddr>) {
    serve_with(listener, vault, MAX_CONNS)
}

/// [`serve`] with an explicit admission cap (tests shrink it).
pub(super) fn serve_with(listener: TcpListener, vault: Option<std::net::SocketAddr>, max: usize) {
    let limiter = Limiter::new(max);
    let live = Arc::new(Liveness::new(vault));
    for stream in listener.incoming() {
        match stream {
            Ok(s) => match limiter.try_acquire() {
                Some(permit) => {
                    let live = Arc::clone(&live);
                    // A failed spawn drops the closure, closing the
                    // connection and releasing the permit; the process
                    // must survive thread exhaustion to keep answering.
                    if let Err(e) = std::thread::Builder::new().spawn(move || {
                        handle(s, &live);
                        drop(permit);
                    }) {
                        log::err(&format!(
                            "gatekeeper: cannot spawn a handler ({e}); connection refused"
                        ));
                        std::thread::sleep(ACCEPT_BACKOFF);
                    }
                }
                None => reject(s),
            },
            Err(e) => {
                // A failure the next accept will not clear (descriptor or
                // memory exhaustion) leaves the listener readable, so
                // continuing would spin the accept loop: back off briefly.
                // Per-connection failures (a reset before accept) need no
                // pause.
                if !is_per_connection(&e) {
                    std::thread::sleep(ACCEPT_BACKOFF);
                }
                continue;
            }
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

/// Answer an over-limit connection without a handler thread: 503, closed.
/// Same wire shape as [`VAULT_DOWN`] — to a client, overload and a down
/// vault are the same verdict.
fn reject(mut s: TcpStream) {
    respond(&mut s, VAULT_DOWN.0, VAULT_DOWN.1);
    let _ = s.shutdown(std::net::Shutdown::Both);
}

/// The single place response bytes are produced: a canned status line, no
/// body, every connection closed. Both the denial path and the handler use
/// it, so the two-response invariant is auditable at one line.
fn respond(stream: &mut TcpStream, code: &str, text: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {code} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
}

/// One request, one response, connection closed. Only the first request
/// line is inspected; malformed, truncated, or oversized requests are just
/// another denied request — the probe (and thus vaultwarden) is never
/// touched by non-`/alive` traffic. A dead socket closes without a
/// response — there is nothing to answer; a head that times out is denied
/// like any other non-request.
pub(super) fn handle(stream: TcpStream, live: &Liveness) {
    handle_with(stream, live, READ_TIMEOUT)
}

/// [`handle`] with an explicit budget for the whole request head (tests
/// shrink it). The budget covers the WHOLE head, not each read: a peer
/// drip-feeding bytes can never hold an admission slot past it (a
/// slowloris would otherwise occupy one for hours).
pub(super) fn handle_with(mut stream: TcpStream, live: &Liveness, budget: Duration) {
    let deadline = Instant::now() + budget;
    let mut buf = [0u8; REQ_CAP];
    let mut used = 0;
    let line = loop {
        if let Some(pos) = buf[..used].iter().position(|&b| b == b'\n') {
            break line_of(&buf[..pos]);
        }
        if used == buf.len() {
            break String::new();
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            // The head did not arrive inside the budget: deny and free
            // the slot rather than waiting on more bytes.
            break String::new();
        }
        if stream.set_read_timeout(Some(remaining)).is_err() {
            return;
        }
        match stream.read(&mut buf[used..]) {
            Ok(0) => break line_of(&buf[..used]),
            Ok(n) => used += n,
            // A timed-out head is a denied request, not a dead socket:
            // answer it so the peer learns the verdict (and the budget
            // stays observable end to end).
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break String::new();
            }
            Err(_) => return,
        }
    };
    let mut parts = line.split_whitespace();
    let alive = parts.next() == Some("GET")
        && parts
            .next()
            .map(target_path)
            .and_then(|target| target.split('?').next())
            .is_some_and(|path| path == "/alive");
    let (code, text) = if !alive {
        ("403", "Forbidden")
    } else if live.alive() {
        ("200", "OK")
    } else {
        VAULT_DOWN
    };
    respond(&mut stream, code, text);
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

/// Whether an accept error is per-connection (the next accept is
/// unaffected) rather than a persistent condition that needs a backoff.
/// EMFILE/ENFILE/ENOMEM/ENOBUFS keep the listener readable, so pausing is
/// what stops the loop from spinning on them.
pub(super) fn is_per_connection(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(code) if code == nix::libc::ECONNABORTED || code == nix::libc::EINTR
    )
}

/// The request target's path per RFC 7230 §5.3: origin-form `/path?query`
/// passes through (minus query); absolute-form
/// `scheme://authority/path?query` contributes the part after the
/// authority. Authority-form and asterisk-form never match `/alive`.
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
