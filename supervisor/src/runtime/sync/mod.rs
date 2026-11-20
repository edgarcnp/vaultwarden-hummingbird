//! S3 state sync over the in-crate client ([`crate::s3`]): persistence of
//! the durable set across `/data` and `/state` on ephemeral redeploys.
//! Siblings: `state` (the pull, the boot reconciliation, and the shared
//! bucket metadata), `push` (the upload, tombstone, and GC side), `synced`
//! (the file-set policy both directions filter through), `manifest` (the
//! bucket-side record with
//! hashes), and `cache` (the local hash cache).

mod cache;
mod manifest;
mod push;
mod state;
mod synced;
mod tombstone;

#[cfg(test)]
mod test_support;

pub use push::{sync_state, wait_for_rsa_key};
pub use state::restore_state;
