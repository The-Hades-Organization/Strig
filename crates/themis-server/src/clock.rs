//! Clocks the server and the client read, injected so tests never sleep.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A source of milliseconds.
///
/// The server reads the instant of every decision from it (milliseconds since the Unix epoch). The
/// client's circuit breaker reads its timers from it, where only differences matter.
pub trait Clock: Send + Sync {
    /// The current instant, or `None` when the clock cannot say (a host clock set before the
    /// epoch). The server answers 503 then: it never decides at an invented instant.
    fn now_ms(&self) -> Option<u64>;
}

/// The host wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> Option<u64> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        u64::try_from(elapsed.as_millis()).ok()
    }
}

/// A monotonic clock that starts at zero when it is created, immune to wall-clock steps. Fit for
/// timers, not for dates.
#[derive(Debug, Clone, Copy)]
pub struct MonotonicClock {
    start: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self { start: Instant::now() }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now_ms(&self) -> Option<u64> {
        u64::try_from(self.start.elapsed().as_millis()).ok()
    }
}

/// A clock you move by hand. Clones share the same instant.
#[derive(Debug, Clone, Default)]
pub struct ManualClock {
    now: Arc<AtomicU64>,
}

impl ManualClock {
    pub fn new(now_ms: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now_ms)),
        }
    }

    pub fn set(&self, now_ms: u64) {
        self.now.store(now_ms, Ordering::SeqCst);
    }

    pub fn advance(&self, by_ms: u64) {
        self.now.fetch_add(by_ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> Option<u64> {
        Some(self.now.load(Ordering::SeqCst))
    }
}

/// A clock that never answers, to prove the server refuses to decide without an instant.
#[derive(Debug, Clone, Copy, Default)]
pub struct BrokenClock;

impl Clock for BrokenClock {
    fn now_ms(&self) -> Option<u64> {
        None
    }
}
