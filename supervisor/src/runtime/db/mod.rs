//! Postgres plumbing shared by the DB features: the rustls-backed client
//! ([`pg`]) and the keepalive ping runner ([`keepalive`]).
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod keepalive;
pub(crate) mod pg;

pub use keepalive::tick as db_keepalive_tick;
