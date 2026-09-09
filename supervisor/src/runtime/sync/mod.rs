//! rclone-backed S3 state sync: /data identity persistence across
//! ephemeral redeploys.

mod state;

pub use state::{restore_state, sync_state};
