//! S3 state sync over the in-crate client ([`crate::s3`]): /data identity
//! persistence across ephemeral redeploys. Siblings: `state` (the
//! push/pull operations) and `identity` (the file-set policy both
//! directions filter through).

mod identity;
mod state;

pub use state::{restore_state, sync_state};
