//! S3 DB backup (opt-in via SUPERVISOR_DB_BACKUP*): periodic consistent
//! dumps of the vault's database pushed to `<state remote>/db`, pruned to
//! keep-N per backend — plus an opt-in boot-time restore into an empty DB.
//!
//! Grouped per backend, one folder each: `postgres/` (pg_dump dump,
//! emptiness gate + pg_restore import), `mariadb/` (mariadb-dump dump,
//! gate + import), `sqlite/` (VACUUM INTO dump, gate + rename import).
//! The orchestrators `dump` (periodic cycle: sweep -> dump -> push ->
//! prune) and `restore` (boot-time restore) dispatch into the backend
//! folders; `check` dispatches the emptiness gate; `tools` runs the
//! bounded external commands (rclone push/prune + dump/restore binaries),
//! `staging` owns the staging dir, `timestamp` the object names.
//!
//! Consistency per backend: postgres via `pg_dump` (MVCC snapshot, no
//! downtime); mysql via `mariadb-dump --single-transaction` (InnoDB
//! snapshot); sqlite via `VACUUM INTO` (consistent copy under WAL).
//! Every phase is bounded and non-fatal: a failed backup logs and
//! continues; the vault never waits on it.
//!
//! Safety model (miss-never-corrupt): dumps stage on the data volume and
//! are pushed to a NEW timestamped object (S3 objects are atomic — a
//! partial upload never materializes); pruning runs strictly after a
//! successful push. A kill at any point costs at most a missed backup,
//! never a corrupt one. Nothing here writes to the live DB except the
//! opt-in restore, which only ever touches a verifiably empty database.
//! Secrets ride env / a 0600 defaults-file — never argv.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod check;
mod dump;
mod mariadb;
mod postgres;
mod prune;
mod restore;
mod sqlite;
mod staging;
#[cfg(test)]
mod support;
mod timestamp;
mod tools;

pub use dump::tick;
pub use restore::restore_if_empty;
