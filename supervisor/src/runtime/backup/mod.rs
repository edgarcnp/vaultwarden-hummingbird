//! S3 DB backup (opt-in via SUPERVISOR_DB_BACKUP*): periodic consistent
//! dumps of the vault's database pushed to `<state remote>/db`, pruned to
//! keep-N per backend — plus an opt-in boot-time restore into an empty DB.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod check;
mod dump;
mod import;
mod prune;
mod staging;
#[cfg(test)]
mod support;
mod timestamp;
mod tools;

pub use dump::tick;
pub use import::restore_if_empty;
