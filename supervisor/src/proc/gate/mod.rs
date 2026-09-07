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
//!
//! Split: `server` is the exposure server; `probe` is the loopback vault
//! probe shared with `healthcheck`, the one-shot image-HEALTHCHECK mode.

mod healthcheck;
mod probe;
mod server;
#[cfg(test)]
mod tests;

pub use healthcheck::healthcheck;
pub use server::{bind, describe, serve};
