//! rclone-backed S3 state sync: /data identity persistence across
//! ephemeral redeploys.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod state;

pub use state::{restore_state, sync_state};
