//! S3 state sync over the in-crate client ([`crate::s3`]): /data identity
//! persistence across ephemeral redeploys.

mod state;

pub use state::{restore_state, sync_state};
