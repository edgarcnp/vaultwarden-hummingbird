//! Config resolution: process env + optional supervisor-owned dotenv file.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod knobs;
mod merge;

pub use knobs::is_supervisor_key;
pub(crate) use knobs::parse_bool;
pub use merge::Config;
