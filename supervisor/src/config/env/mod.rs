//! Resolves the supervisor knobs and the vaultwarden child env from the
//! process environment and the strict dotenv file. [`Config`] is the single
//! resolved snapshot; `knobs` holds the parsers, `schema` the key inventory.

mod knobs;
mod merge;
pub(crate) mod schema;

pub use knobs::{is_supervisor_consumed, is_supervisor_key, vaultwarden_key};
pub(crate) use knobs::{parse_count, parse_flag};
pub use merge::{Config, EarlyConfig};
