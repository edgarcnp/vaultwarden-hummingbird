//! The maintenance reactor: one scheduler thread owns every periodic task
//! (DB backup, state sync) and the final shutdown flush.
//!
//! Why one thread: the tasks share durability resources (staging dir, the
//! lineage sidecar, the bucket keyspace) with no locks between them. As
//! detached threads, an interval tick could overlap the shutdown tick and
//! even sweep away the other's staged dump. Here exactly one thread ever
//! starts a task or a final flush after boot, so writers cannot overlap.
//!
//! Shutdown protocol: the watch loop asks the reactor to stop as soon as it
//! decides to shut down. The stop token is monotonic — never cleared (the
//! process stop flag is consumed by `take_stop`, so it cannot serve this
//! purpose) — so an in-flight tick aborts at its next check. [`Reactor::drain`]
//! then runs the final flushes on the same thread in task order (DB dump
//! before state push), bounded by a deadline; a stop request observed while
//! draining shortens that deadline.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use super::backup::tick as backup_tick;
use super::sync::sync_state;
use super::{POLL, stopping};
use crate::config::{
    BACKUP_FIRST_DELAY, DbBackupConfig, SYNC_FIRST_DELAY, SYNC_TIMEOUT, SyncConfig,
};
use crate::util::log;

/// Monotonic maintenance lifecycle token. `stop` is set at most once and
/// never cleared: an in-flight abort closure keeps seeing it until the
/// process exits.
pub struct Token {
    stop: AtomicBool,
    forced: AtomicBool,
}

impl Token {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            forced: AtomicBool::new(false),
        }
    }

    /// Whether the shutdown drain has been requested (periodic runs abort).
    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Whether a stop request arrived while draining ("hurry up").
    pub fn forced(&self) -> bool {
        self.forced.load(Ordering::SeqCst)
    }

    fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    fn force(&self) {
        self.forced.store(true, Ordering::SeqCst);
    }
}

/// Periodic invocation; the token is the run's abort source.
type RunFn = Box<dyn Fn(&Token) + Send>;
/// Final invocation; the closure receives the deadline-based abort.
type FinishFn = Box<dyn Fn(&dyn Fn() -> bool) + Send>;

/// One schedulable task: a periodic run (disabled when `cadence` is `None`)
/// plus an optional final flush at drain. Constructors capture their config;
/// both invocations stay cancellable.
pub(crate) struct Task {
    name: &'static str,
    first_delay: Duration,
    cadence: Option<Duration>,
    run: RunFn,
    finish: Option<FinishFn>,
}

impl Task {
    /// The periodic DB backup. Callers pass it only for periodic configs
    /// (restore-only backup setups have no final dump either, as before).
    pub(crate) fn backup(cfg: DbBackupConfig) -> Self {
        let periodic = cfg.clone();
        Self {
            name: "db backup",
            first_delay: BACKUP_FIRST_DELAY,
            cadence: Some(cfg.interval),
            run: Box::new(move |token| backup_tick(&periodic, || token.stopping())),
            finish: Some(Box::new(move |abort| backup_tick(&cfg, abort))),
        }
    }

    /// The state push. A zero interval means "no periodic pushes" but keeps
    /// the shutdown flush, matching the pre-reactor behavior.
    pub(crate) fn sync(cfg: SyncConfig) -> Self {
        let periodic = cfg.clone();
        Self {
            name: "state sync",
            first_delay: SYNC_FIRST_DELAY,
            cadence: (!cfg.interval.is_zero()).then_some(cfg.interval),
            run: Box::new(move |token| {
                let _ = sync_state(&periodic, || token.stopping());
            }),
            finish: Some(Box::new(move |abort| {
                let _ = sync_state(&cfg, abort);
            })),
        }
    }
}

enum Command {
    Drain {
        deadline: Instant,
        forced_deadline: Instant,
    },
}

enum Wait {
    Command(Command),
    Timeout,
    Closed,
}

/// The reactor handle: owns the scheduler thread until [`Self::drain`].
pub struct Reactor {
    token: Arc<Token>,
    tx: Sender<Command>,
    handle: std::thread::JoinHandle<()>,
}

impl Reactor {
    /// Start the reactor for the given (feature-filtered) tasks. `None`
    /// when there is nothing to schedule. A thread that cannot start is a
    /// failed boot, not a degraded one: maintenance silently ceasing to
    /// exist is worse than refusing to run.
    pub fn start(tasks: Vec<Task>) -> Option<Self> {
        if tasks.is_empty() {
            return None;
        }
        let token = Arc::new(Token::new());
        let (tx, rx) = channel();
        let thread_token = Arc::clone(&token);
        let handle = std::thread::Builder::new()
            .name("maintenance".into())
            .spawn(move || run(tasks, rx, thread_token))
            .expect("maintenance thread");
        Some(Self { token, tx, handle })
    }

    /// Ask the reactor to stop scheduling periodic work. Monotonic; call it
    /// as soon as shutdown is decided so an in-flight tick aborts promptly.
    pub fn stop(&self) {
        self.token.request_stop();
    }

    /// Stop, wait for the in-flight tick, run the final flushes in task
    /// order, and join the thread. `budget` bounds the flush; a stop request
    /// observed while draining shortens it to `forced_budget`. A thread
    /// still draining one S3 call past the budget is left behind — the
    /// process exits anyway, and only that upload is lost.
    pub fn drain(self, budget: Duration, forced_budget: Duration) {
        self.drain_with(budget, forced_budget, stopping);
    }

    /// [`Self::drain`] with the hurry-up source injected (tests).
    fn drain_with(self, budget: Duration, forced_budget: Duration, hurry: impl Fn() -> bool) {
        self.token.request_stop();
        let deadline = Instant::now() + budget;
        let forced_deadline = Instant::now() + forced_budget;
        let _ = self.tx.send(Command::Drain {
            deadline,
            forced_deadline,
        });
        let hard_stop = deadline + SYNC_TIMEOUT;
        while !self.handle.is_finished() {
            if hurry() {
                self.token.force();
            }
            if Instant::now() >= hard_stop {
                log::err("maintenance: still draining at the hard deadline; exiting anyway");
                return; // dropping the handle detaches a stuck thread
            }
            std::thread::sleep(POLL);
        }
        if self.handle.join().is_err() {
            log::err("maintenance: thread panicked during drain");
        }
    }
}

/// Scheduler loop: run each due task (sequentially, in declaration order),
/// then sleep until the earliest next due time or a drain command.
fn run(mut tasks: Vec<Task>, rx: Receiver<Command>, token: Arc<Token>) {
    let mut due: Vec<Option<Instant>> = tasks
        .iter()
        .map(|task| task.cadence.map(|_| Instant::now() + task.first_delay))
        .collect();
    loop {
        let now = Instant::now();
        for (i, task) in tasks.iter_mut().enumerate() {
            if due[i].is_some_and(|at| now >= at) {
                due[i] = task.cadence.map(|c| Instant::now() + c);
                // A stop already observed means a drain is coming: never
                // start new periodic work after it.
                if token.stopping() {
                    continue;
                }
                (task.run)(&token);
            }
        }
        let next = due.iter().flatten().min().copied();
        let timeout = next.map(|at| at.saturating_duration_since(Instant::now()));
        match wait_for_command(&rx, timeout) {
            Wait::Command(Command::Drain {
                deadline,
                forced_deadline,
            }) => {
                flush(tasks, deadline, forced_deadline, &token);
                return;
            }
            Wait::Timeout => {}
            Wait::Closed => return,
        }
    }
}

fn wait_for_command(rx: &Receiver<Command>, timeout: Option<Duration>) -> Wait {
    match timeout {
        Some(t) => match rx.recv_timeout(t) {
            Ok(cmd) => Wait::Command(cmd),
            Err(RecvTimeoutError::Timeout) => Wait::Timeout,
            Err(RecvTimeoutError::Disconnected) => Wait::Closed,
        },
        None => match rx.recv() {
            Ok(cmd) => Wait::Command(cmd),
            Err(_) => Wait::Closed,
        },
    }
}

/// The final flushes, in task order. Each gets a deadline-based abort so a
/// slow bucket cannot hold the container open past the shutdown budget;
/// once the deadline passed, later tasks are skipped rather than started.
fn flush(tasks: Vec<Task>, deadline: Instant, forced_deadline: Instant, token: &Token) {
    let abort = || {
        Instant::now()
            >= if token.forced() {
                forced_deadline
            } else {
                deadline
            }
    };
    for task in tasks {
        let Some(finish) = task.finish else {
            continue;
        };
        if abort() {
            log::err(&format!(
                "maintenance: {} final flush skipped (persist budget exhausted)",
                task.name
            ));
            continue;
        }
        finish(&abort);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A task whose periodic run blocks until the drain token is set, so
    /// the test can prove the monotonic stop reaches an in-flight run.
    fn counting_task(
        runs: Arc<AtomicUsize>,
        finals: Arc<AtomicUsize>,
        saw_stop: Arc<AtomicBool>,
    ) -> Task {
        Task {
            name: "test",
            first_delay: Duration::from_millis(10),
            cadence: Some(Duration::from_millis(10)),
            run: Box::new(move |token| {
                let give_up = Instant::now() + Duration::from_secs(3);
                while !token.stopping() && Instant::now() < give_up {
                    std::thread::sleep(Duration::from_millis(2));
                }
                saw_stop.store(token.stopping(), Ordering::SeqCst);
                runs.fetch_add(1, Ordering::SeqCst);
            }),
            finish: Some(Box::new(move |abort| {
                assert!(!abort(), "a fresh budget must not abort the final flush");
                finals.fetch_add(1, Ordering::SeqCst);
            })),
        }
    }

    /// Drain stops the in-flight tick (the monotonic token is observed),
    /// runs the final flush exactly once, and schedules nothing after.
    #[test]
    fn drain_stops_in_flight_work_and_flushes_once() {
        let runs = Arc::new(AtomicUsize::new(0));
        let finals = Arc::new(AtomicUsize::new(0));
        let saw_stop = Arc::new(AtomicBool::new(false));
        let reactor = Reactor::start(vec![counting_task(
            Arc::clone(&runs),
            Arc::clone(&finals),
            Arc::clone(&saw_stop),
        )])
        .expect("one task starts the reactor");

        // Let the periodic run begin; it blocks on the token.
        std::thread::sleep(Duration::from_millis(50));
        reactor.drain(Duration::from_secs(2), Duration::from_millis(500));

        assert_eq!(runs.load(Ordering::SeqCst), 1, "one periodic run");
        assert!(
            saw_stop.load(Ordering::SeqCst),
            "the in-flight run must observe the monotonic stop"
        );
        assert_eq!(finals.load(Ordering::SeqCst), 1, "one final flush");
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "nothing runs after the drain"
        );
    }

    /// A task without a cadence never runs periodically but still flushes at
    /// shutdown (the zero-interval state sync).
    #[test]
    fn a_cadence_less_task_only_flushes() {
        let runs = Arc::new(AtomicUsize::new(0));
        let finals = Arc::new(AtomicUsize::new(0));
        let run_flag = Arc::clone(&runs);
        let finish_flag = Arc::clone(&finals);
        let reactor = Reactor::start(vec![Task {
            name: "final-only",
            first_delay: Duration::ZERO,
            cadence: None,
            run: Box::new(move |_| {
                run_flag.fetch_add(1, Ordering::SeqCst);
            }),
            finish: Some(Box::new(move |_| {
                finish_flag.fetch_add(1, Ordering::SeqCst);
            })),
        }])
        .expect("one task starts the reactor");

        std::thread::sleep(Duration::from_millis(30));
        reactor.drain(Duration::from_secs(2), Duration::from_secs(1));
        assert_eq!(runs.load(Ordering::SeqCst), 0, "no periodic run");
        assert_eq!(finals.load(Ordering::SeqCst), 1, "shutdown flush ran");
    }

    /// The final flush is deadline-bounded: a stuck finish must end at the
    /// budget, not run forever.
    #[test]
    fn final_flush_aborts_at_the_budget() {
        let saw_abort = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&saw_abort);
        let task = Task {
            name: "stuck",
            first_delay: Duration::from_secs(3600),
            cadence: Some(Duration::from_secs(3600)),
            run: Box::new(|_| panic!("must not run periodically")),
            finish: Some(Box::new(move |abort| {
                let give_up = Instant::now() + Duration::from_secs(5);
                while !abort() && Instant::now() < give_up {
                    std::thread::sleep(Duration::from_millis(2));
                }
                flag.store(abort(), Ordering::SeqCst);
            })),
        };
        let start = Instant::now();
        Reactor::start(vec![task])
            .expect("one task starts the reactor")
            .drain(Duration::from_millis(80), Duration::from_millis(40));
        assert!(
            saw_abort.load(Ordering::SeqCst),
            "the flush must see the budget abort"
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "bounded by the budget, took {:?}",
            start.elapsed()
        );
    }

    /// A hurry-up request observed while draining shortens the budget: the
    /// same stuck flush ends at the forced budget instead of the full one.
    #[test]
    fn a_hurry_up_shortens_the_flush_budget() {
        let elapsed_ms = Arc::new(AtomicUsize::new(0));
        let flag = Arc::clone(&elapsed_ms);
        let task = Task {
            name: "stuck",
            first_delay: Duration::from_secs(3600),
            cadence: Some(Duration::from_secs(3600)),
            run: Box::new(|_| panic!("must not run periodically")),
            finish: Some(Box::new(move |abort| {
                let start = Instant::now();
                while !abort() && start.elapsed() < Duration::from_secs(10) {
                    std::thread::sleep(Duration::from_millis(2));
                }
                flag.store(start.elapsed().as_millis() as usize, Ordering::SeqCst);
            })),
        };
        Reactor::start(vec![task])
            .expect("one task starts the reactor")
            // Full budget 10s would dominate the test; the hurry-up must end
            // the flush at the forced 60ms instead.
            .drain_with(Duration::from_secs(10), Duration::from_millis(60), || true);
        let elapsed = Duration::from_millis(elapsed_ms.load(Ordering::SeqCst) as u64);
        assert!(
            elapsed < Duration::from_secs(3),
            "the forced budget must shorten the flush, took {elapsed:?}"
        );
    }
}
