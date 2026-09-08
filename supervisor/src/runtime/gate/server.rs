//! The exposure server: bind the public port, answer `/alive` with the
//! vault's verdict, refuse everything else. std-only (no HTTP crate); the
//! surface is deliberately two responses wide. Denied requests are not
//! logged (platform health probes and drive-by scanners would otherwise
//! dominate the container log). Every path is bounded: read/probe timeouts,
//! capped request size, `Connection: close`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use super::probe::{PROBE_TIMEOUT, get_alive};

use crate::util::log;

/// One bounded read buffer for the request head; the decision only needs
/// the first line.
const REQ_CAP: usize = 2048;
/// No request may hold a gatekeeper thread for longer than this.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Probe result when vaultwarden does not answer 2xx: health checks must
/// see the vault, not just the container.
const VAULT_DOWN: (&str, &str) = ("503", "Service Unavailable");

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
/// listener's lifetime; shutdown closes the process, not the loop. One
/// thread per connection (probes are rare; thread lifetime capped by
/// [`READ_TIMEOUT`]).
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

/// One request, one response, connection closed. Only the first request
/// line is inspected; malformed, truncated, or oversized requests are just
/// another denied request — the probe (and thus vaultwarden) is never
/// touched by non-`/alive` traffic. A read error closes the connection
/// without a response — there is nothing to answer.
pub(super) fn handle(mut stream: TcpStream, vault: Option<std::net::SocketAddr>) {
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

/// Bounded liveness probe of vaultwarden's `/alive`; any failure is a
/// plain `false` (the caller answers 503).
fn probe_vault(vault: Option<std::net::SocketAddr>) -> bool {
    vault.is_some_and(|addr| get_alive(addr, PROBE_TIMEOUT))
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
