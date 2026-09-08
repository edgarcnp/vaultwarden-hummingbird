//! SQLite backend for the DB backup: dump ([`dump`], `VACUUM INTO`) and
//! restore ([`restore`], emptiness gate + integrity-checked rename). All
//! in-process via bundled rusqlite — no external tool.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod dump;
mod restore;

pub(crate) use dump::dump;
pub(crate) use restore::{import, is_empty};
