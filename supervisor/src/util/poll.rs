//! Bounded waiting: one generic poll loop for "check until it answers,
//! a timeout passes, or a stop request fires". Every bounded phase shares
//! the same shape — check first, then abort/deadline, then sleep a slice —
//! so the loop lives here once; callers keep only their check and policy.
//! Sleep slices are capped at the remaining budget, so termination is by
//! construction.

use std::time::{Duration, Instant};

/// Poll `check` until it returns `Some` (the wait succeeds), `abort`
/// fires, or `timeout` passes (`None` = timeout or abort; callers that
/// must distinguish the two consult their own stop flag). `check` runs
/// before every exit condition, so a readiness that lands in the same
/// tick as a stop request still wins. The sleep slice is the caller's
/// `tick` capped at the remaining budget.
pub fn wait_until<T>(
    mut check: impl FnMut() -> Option<T>,
    timeout: Duration,
    abort: impl Fn() -> bool,
    tick: Duration,
) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = check() {
            return Some(value);
        }
        if abort() || Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(tick.min(deadline.saturating_duration_since(Instant::now())));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    #[test]
    fn returns_the_value_when_check_answers() {
        let n = AtomicUsize::new(0);
        let got = wait_until(
            || {
                let v = n.fetch_add(1, Ordering::Relaxed);
                (v >= 2).then_some(v)
            },
            Duration::from_secs(5),
            || false,
            Duration::from_millis(1),
        );
        assert_eq!(got, Some(2));
    }

    #[test]
    fn timeout_returns_none_and_is_bounded() {
        let start = Instant::now();
        let got = wait_until::<()>(
            || None,
            Duration::from_millis(150),
            || false,
            Duration::from_millis(10),
        );
        assert_eq!(got, None);
        assert!(start.elapsed() >= Duration::from_millis(150));
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn abort_beats_the_timeout() {
        let start = Instant::now();
        let got = wait_until::<()>(
            || None,
            Duration::from_secs(60),
            || true,
            Duration::from_millis(10),
        );
        assert_eq!(got, None);
        assert!(start.elapsed() < Duration::from_secs(30));
    }

    /// A readiness that lands in the same tick as the abort wins: check
    /// runs first.
    #[test]
    fn check_wins_over_a_simultaneous_abort() {
        let hit = Arc::new(AtomicUsize::new(0));
        let hit2 = Arc::clone(&hit);
        let got = wait_until(
            move || Some(hit2.fetch_add(1, Ordering::Relaxed)),
            Duration::from_secs(60),
            || true,
            Duration::from_millis(10),
        );
        assert_eq!(got, Some(0));
    }

    /// Zero timeout with a failing check returns None promptly (the
    /// deadline is checked after the first check).
    #[test]
    fn zero_timeout_checks_once() {
        let n = AtomicUsize::new(0);
        let got = wait_until::<()>(
            || {
                n.fetch_add(1, Ordering::Relaxed);
                None
            },
            Duration::ZERO,
            || false,
            Duration::from_millis(10),
        );
        assert_eq!(got, None);
        assert_eq!(n.load(Ordering::Relaxed), 1);
    }
}
