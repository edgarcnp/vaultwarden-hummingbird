//! Exposed-port gatekeeper: the only listener on the container's public
//! port, and it answers only `GET /alive` with the vault's verdict (see
//! `server`); every other request is refused. The Bitwarden API lives on a
//! loopback-only port that only `tailscale serve` can reach. Siblings:
//! `probe` (loopback vault probe, shared with `healthcheck`), `healthcheck`
//! (one-shot image HEALTHCHECK mode), `limiter` (handler admission cap),
//! `liveness` (TTL-cached `/alive` verdicts).

mod healthcheck;
mod limiter;
mod liveness;
mod probe;
mod server;
#[cfg(test)]
mod tests;

pub use healthcheck::healthcheck;
pub use server::{bind, describe, serve};
