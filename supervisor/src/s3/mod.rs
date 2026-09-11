//! In-process S3 transport: the minimal client the supervisor's optional
//! persistence features share (state sync, DB backup). Grouped here so
//! the transport stays independent of any one feature's configuration —
//! callers resolve their knobs into a [`RemoteSpec`] and connect.
//!
//! Siblings: `client` (put/get/list/delete over one bucket), `remote`
//! (the resolved remote as pure data).

mod client;
mod remote;

pub use client::{Client, Listed};
pub use remote::RemoteSpec;
