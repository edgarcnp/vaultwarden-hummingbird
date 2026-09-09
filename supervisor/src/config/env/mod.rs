//! Config resolution: process env + optional supervisor-owned dotenv file.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod knobs;
mod merge;

pub(crate) use knobs::parse_bool;
pub use knobs::{is_supervisor_key, vaultwarden_key};
pub use merge::Config;
