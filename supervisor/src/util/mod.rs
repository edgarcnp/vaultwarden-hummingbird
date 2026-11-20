//! Small cross-cutting helpers that belong to no single runtime module:
//! descriptor-anchored filesystem access, hashing, logging, bounded polling,
//! and staged files. Each helper states its own contract at the item.

pub(crate) mod fs;
pub mod hash;
pub mod log;
pub mod net;
mod poll;
mod staged;

pub use fs::make_private;
pub use poll::wait_until;
pub use staged::StagedFile;
pub use sync::lock_ignoring_poison;

mod sync {
    //! Poison-tolerant locking for status slots and registries.

    use std::sync::{Mutex, MutexGuard};

    /// Take a lock, recovering a poisoned one instead of propagating the
    /// panic: the guarded state is a status slot or registry, not an
    /// invariant left half-updated.
    pub fn lock_ignoring_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}
