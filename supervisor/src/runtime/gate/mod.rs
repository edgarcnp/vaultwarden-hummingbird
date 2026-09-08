//! Exposed-port gatekeeper: the only listener on the container's public
//! port. The Bitwarden API lives on a loopback-only port that only
//! `tailscale serve` can reach; this listener reports vault liveness and
//! refuses everything else (see `server`). Siblings: `probe` (loopback
//! vault probe, shared with `healthcheck`), `healthcheck` (one-shot image
//! HEALTHCHECK mode).

mod healthcheck;
mod probe;
mod server;
#[cfg(test)]
mod tests;

pub use healthcheck::healthcheck;
pub use server::{bind, describe, serve};
