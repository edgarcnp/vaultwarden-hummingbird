//! Config resolution: process env + optional supervisor-owned dotenv file.

mod knobs;
mod merge;

pub(crate) use knobs::parse_flag;
pub use knobs::{is_supervisor_key, vaultwarden_key};
pub use merge::Config;
