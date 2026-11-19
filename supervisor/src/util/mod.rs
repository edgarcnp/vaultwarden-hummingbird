//! Small shared helpers with no single owner module.

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
    use std::sync::{Mutex, MutexGuard};

    /// Take a lock; a poisoned lock is recovered rather than propagating a
    /// panic (the guarded state is a status slot or registry, not a
    /// half-updated invariant).
    pub fn lock_ignoring_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}
