//! Config resolution: process env + optional supervisor-owned dotenv file.

mod knobs;
mod merge;

pub use knobs::{is_supervisor_key, vaultwarden_key};
pub(crate) use knobs::{parse_count, parse_flag};
pub use merge::Config;
