//! In-process S3 transport: the minimal client the supervisor's optional
//! persistence features share (state sync, DB backup). Callers resolve
//! their knobs into a [`RemoteSpec`] and connect; config resolution owns
//! the CA-location policy (a custom bundle must live on the supervisor-only
//! state volume), so this layer only parses the validated file.
//!
//! Siblings: `client` (put/get/list/delete over one bucket), `remote`
//! (the resolved remote as pure data).

mod client;
mod remote;
mod transport;

pub use client::{Client, Expect, GetError, Listed, MAX_DB_OBJECT_BYTES, MAX_SYNC_OBJECT_BYTES};
pub use remote::{BucketStyle, RemoteSpec};
pub use transport::validate_ca_file;
