//! In-process S3 transport: the minimal client the supervisor's optional
//! persistence features share (state sync, DB backup). Callers resolve
//! their knobs into a [`RemoteSpec`] and connect; the only image-wide
//! policy here is that a custom CA bundle must live on the supervisor-only
//! state volume.
//!
//! Siblings: `client` (put/get/list/delete over one bucket), `remote`
//! (the resolved remote as pure data).

mod client;
mod remote;

pub use client::{
    Client, Expect, GetError, Listed, MAX_DB_OBJECT_BYTES, MAX_SYNC_OBJECT_BYTES, validate_ca_file,
};
pub use remote::{BucketStyle, RemoteSpec};
