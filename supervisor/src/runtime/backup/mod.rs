//! S3 DB backup (opt-in via SUPERVISOR_DB_BACKUP*): periodic consistent
//! dumps of the vault's sqlite database pushed to `<state remote>/db`,
//! pruned to keep-N — plus an opt-in boot-time restore into an empty DB.
//!
//! The orchestrators `dump` (sweep -> dump -> push -> prune) and `restore`
//! (boot-time) drive the in-process sqlite paths (`sqlite/`); `check`
//! dispatches the emptiness gate; `tools` runs the bounded external rclone
//! commands, `staging` owns the staging dir, `timestamp` the object names.
//!
//! Consistency: sqlite via `VACUUM INTO` (consistent copy under WAL).
//! Every phase is bounded and non-fatal: a failed backup logs and
//! continues; the vault never waits on it.
//!
//! Safety model (miss-never-corrupt): dumps stage on the data volume and
//! are pushed to a NEW timestamped object (S3 objects are atomic — a
//! partial upload never materializes); pruning runs strictly after a
//! successful push. Nothing here writes to the live DB except the opt-in
//! restore, which only ever touches a verifiably empty database.

mod check;
mod dump;
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
