//! External DB client tool plumbing, one module per backend: postgres
//! ([`postgres`], libpq env for pg_dump/pg_restore) and mysql/mariadb
//! ([`mariadb`], defaults-file + shared-lib env for mariadb-dump/mariadb).
//! The supervisor has no native mysql client — both backends' dump/restore
//! ride these external binaries.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod mariadb;
mod postgres;

pub use mariadb::{defaults_file, mysql_env};
pub use postgres::pg_env;
