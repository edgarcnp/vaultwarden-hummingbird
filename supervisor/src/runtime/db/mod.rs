//! Database access plumbing shared by the DB features: the native
//! rustls-backed postgres client ([`pg`], TLS 1.3 only), the external
//! client tool plumbing ([`tools`], one module per backend — postgres:
//! libpq env for pg_dump/pg_restore; mariadb: defaults-file for
//! mariadb-dump/mariadb — both TLS 1.3 only), and the keepalive ping
//! runner ([`keepalive`]). There is no native mysql client: mysql/mariadb
//! access rides the mariadb CLI tools.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod keepalive;
pub(crate) mod pg;
pub(crate) mod tools;

pub use keepalive::tick as db_keepalive_tick;
