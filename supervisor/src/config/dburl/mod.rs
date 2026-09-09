//! Database URL parsing (`VAULTWARDEN_DATABASE_URL`) into a [`DbSpec`].
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod parse;
mod spec;

pub use parse::{parse, scheme_for_log};
pub use spec::DbSpec;
