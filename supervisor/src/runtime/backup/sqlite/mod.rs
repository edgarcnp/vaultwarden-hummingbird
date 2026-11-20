//! SQLite backend for the DB backup: `VACUUM INTO` dump and
//! integrity-checked rename import, in-process via bundled rusqlite. The
//! live database is pinned through a private directory of hard links before
//! SQLite opens it, so the vault cannot race the open with a FIFO/symlink.

mod dump;
mod private;
mod restore;

pub(crate) use dump::dump;
pub(crate) use restore::{ImportError, import, is_empty};
