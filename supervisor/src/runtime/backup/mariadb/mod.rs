//! MariaDB/MySQL backend for the DB backup.

mod dump;
mod restore;

pub(crate) use dump::dump;
pub(crate) use restore::{import, table_count};
