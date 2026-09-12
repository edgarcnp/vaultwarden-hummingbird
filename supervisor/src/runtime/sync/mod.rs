//! S3 state sync over the in-crate client ([`crate::s3`]): /data
//! persistence across ephemeral redeploys. Siblings: `state` (the
//! push/pull operations) and `synced` (the file-set policy both
//! directions filter through).

mod state;
mod synced;

pub use state::{restore_state, sync_state};
