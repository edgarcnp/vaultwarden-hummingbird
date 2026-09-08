//! MariaDB/MySQL backend for the DB backup: dump ([`dump`],
//! `mariadb-dump`) and restore ([`restore`], emptiness gate + import).
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod dump;
mod restore;

pub(crate) use dump::dump;
pub(crate) use restore::{import, table_count};
