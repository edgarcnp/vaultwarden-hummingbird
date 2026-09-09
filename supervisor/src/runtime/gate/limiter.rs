//! Admission limiting for the gate's handler threads: a counting permit
//! set. Over-limit acquires fail immediately (no queue — the caller
//! answers 503 and closes); permits are RAII, so a handler exiting for
//! any reason (read error, timeout, panic) releases its slot.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The gate's permit set: at most `max` handlers admitted at once.
pub(super) struct Limiter {
    active: Arc<AtomicUsize>,
    max: usize,
}

/// One admitted handler slot; release on drop.
pub(super) struct Permit {
    active: Arc<AtomicUsize>,
}

impl Limiter {
    pub(super) fn new(max: usize) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    /// Take one permit, or `None` at capacity (the caller must reject the
    /// connection instead of queueing it).
    pub(super) fn try_acquire(&self) -> Option<Permit> {
        self.active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < self.max).then_some(n + 1)
            })
            .ok()
            .map(|_| Permit {
                active: Arc::clone(&self.active),
            })
    }

    /// Currently held permits.
    #[cfg(test)]
    pub(super) fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_up_to_max_then_rejects_and_recovers() {
        let limiter = Limiter::new(2);
        let a = limiter.try_acquire().expect("first permit");
        let b = limiter.try_acquire().expect("second permit");
        assert!(limiter.try_acquire().is_none(), "over limit");
        assert_eq!(limiter.active(), 2);
        drop(b);
        assert_eq!(limiter.active(), 1);
        limiter.try_acquire().expect("released slot reusable");
        drop(a);
    }
}
