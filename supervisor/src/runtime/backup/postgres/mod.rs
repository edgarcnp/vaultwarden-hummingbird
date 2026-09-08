//! Postgres backend for the DB backup: dump ([`dump`], `pg_dump`) and
//! restore ([`restore`], emptiness gate + `pg_restore` import).
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod dump;
mod restore;

pub(crate) use dump::dump;
pub(crate) use restore::{import, is_empty};
