//! Database access plumbing shared by the DB features: the native
//! rustls-backed postgres client ([`pg`]), the external pg_dump/pg_restore
//! + mariadb-dump/mariadb client tool plumbing ([`tools`]), and the
//! keepalive ping runner ([`keepalive`]). There is no native mysql client:
//! mysql/mariadb access rides the mariadb CLI tools.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod keepalive;
pub(crate) mod pg;
pub(crate) mod tools;

pub use keepalive::tick as db_keepalive_tick;
