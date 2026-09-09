//! Exposed-port gatekeeper: the only listener on the container's public
//! port. The Bitwarden API lives on a loopback-only port that only
//! `tailscale serve` can reach; this listener reports vault liveness and
//! refuses everything else (see `server`). Siblings: `probe` (loopback
//! vault probe, shared with `healthcheck`), `healthcheck` (one-shot image
//! HEALTHCHECK mode), `limiter` (handler admission cap), `liveness`
//! (single-flight `/alive` verdicts).

mod healthcheck;
mod limiter;
mod liveness;
mod probe;
mod server;
#[cfg(test)]
mod tests;

pub use healthcheck::healthcheck;
pub use server::{bind, describe, serve};
