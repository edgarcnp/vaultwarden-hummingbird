//! SQLite backend for the DB backup: `VACUUM INTO` dump and
//! integrity-checked rename import, in-process via bundled rusqlite.

mod dump;
mod restore;

pub(crate) use dump::dump;
pub(crate) use restore::{import, is_empty};
