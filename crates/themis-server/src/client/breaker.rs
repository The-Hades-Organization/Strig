//! A three-state circuit breaker with an injected clock.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::clock::Clock;

/// When the breaker opens and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BreakerConfig {
    /// Consecutive failures that open a closed circuit.
    pub failure_threshold: u32,
    /// How long an open circuit refuses calls before it lets one probe through.
    pub open_for: Duration,
}

impl BreakerConfig {
    #[must_use]
    pub fn with_failure_threshold(mut self, failures: u32) -> Self {
        self.failure_threshold = failures;
        self
    }

    #[must_use]
    pub fn with_open_for(mut self, open_for: Duration) -> Self {
        self.open_for = open_for;
        self
    }
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_for: Duration::from_secs(30),
        }
    }
}

/// What the breaker is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Calls go through; failures are counted.
    Closed,
    /// Calls are refused until the wait is over.
    Open,
    /// One probe is allowed (or is in flight); its result closes or reopens the circuit.
    HalfOpen,
}

#[derive(Debug, Clone, Copy)]
enum Inner {
    Closed { failures: u32 },
    Open { since_ms: u64 },
    HalfOpen { probing: bool },
}

/// Closed, open with a wait, half-open with one probe.
pub struct CircuitBreaker {
    config: BreakerConfig,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
}

impl CircuitBreaker {
    pub fn new(config: BreakerConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            config,
            clock,
            inner: Mutex::new(Inner::Closed { failures: 0 }),
        }
    }

    pub fn state(&self) -> BreakerState {
        match *self.lock() {
            Inner::Closed { .. } => BreakerState::Closed,
            Inner::Open { .. } => BreakerState::Open,
            Inner::HalfOpen { .. } => BreakerState::HalfOpen,
        }
    }

    /// Asks to make a call. `None` means the circuit refuses it. The permit must be settled with
    /// [`Permit::success`] or [`Permit::failure`]; a permit dropped without either (the call was
    /// cancelled) counts as a failure, so a lost probe cannot leave the circuit half-open forever.
    pub fn acquire(&self) -> Option<Permit<'_>> {
        let now = self.now();
        let mut inner = self.lock();
        let allowed = match *inner {
            Inner::Closed { .. } => true,
            Inner::Open { since_ms } if now.saturating_sub(since_ms) >= self.wait_ms() => {
                *inner = Inner::HalfOpen { probing: true };
                true
            }
            Inner::Open { .. } | Inner::HalfOpen { probing: true } => false,
            Inner::HalfOpen { probing: false } => {
                *inner = Inner::HalfOpen { probing: true };
                true
            }
        };
        drop(inner);
        allowed.then_some(Permit {
            breaker: self,
            settled: false,
        })
    }

    fn wait_ms(&self) -> u64 {
        u64::try_from(self.config.open_for.as_millis()).unwrap_or(u64::MAX)
    }

    /// A clock with no answer reads as time standing still: an open circuit stays open.
    fn now(&self) -> u64 {
        self.clock.now_ms().unwrap_or(0)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // The state is one small `Copy` value, so a poisoned lock holds nothing half-written.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record_success(&self) {
        *self.lock() = Inner::Closed { failures: 0 };
    }

    fn record_failure(&self) {
        let now = self.now();
        let mut inner = self.lock();
        *inner = match *inner {
            Inner::Closed { failures } if failures.saturating_add(1) >= self.config.failure_threshold => {
                Inner::Open { since_ms: now }
            }
            Inner::Closed { failures } => Inner::Closed {
                failures: failures.saturating_add(1),
            },
            Inner::HalfOpen { .. } => Inner::Open { since_ms: now },
            open @ Inner::Open { .. } => open,
        };
    }
}

/// Permission for one call, settled with its outcome.
#[must_use = "settle the permit with success() or failure()"]
pub struct Permit<'a> {
    breaker: &'a CircuitBreaker,
    settled: bool,
}

impl Permit<'_> {
    pub fn success(mut self) {
        self.settled = true;
        self.breaker.record_success();
    }

    pub fn failure(mut self) {
        self.settled = true;
        self.breaker.record_failure();
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.breaker.record_failure();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    fn breaker(threshold: u32, open_ms: u64) -> (CircuitBreaker, ManualClock) {
        let clock = ManualClock::new(1_000);
        let config = BreakerConfig::default()
            .with_failure_threshold(threshold)
            .with_open_for(Duration::from_millis(open_ms));
        (CircuitBreaker::new(config, Arc::new(clock.clone())), clock)
    }

    fn fail(breaker: &CircuitBreaker) {
        breaker.acquire().expect("the circuit lets the call through").failure();
    }

    #[test]
    fn opens_after_consecutive_failures_and_refuses_calls() {
        let (breaker, _) = breaker(3, 100);
        fail(&breaker);
        fail(&breaker);
        assert_eq!(breaker.state(), BreakerState::Closed);
        fail(&breaker);
        assert_eq!(breaker.state(), BreakerState::Open);
        assert!(breaker.acquire().is_none());
    }

    #[test]
    fn a_success_resets_the_failure_count() {
        let (breaker, _) = breaker(2, 100);
        fail(&breaker);
        breaker.acquire().unwrap().success();
        fail(&breaker);
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[test]
    fn lets_one_probe_through_after_the_wait_and_closes_on_success() {
        let (breaker, clock) = breaker(1, 100);
        fail(&breaker);
        clock.advance(99);
        assert!(breaker.acquire().is_none(), "still inside the wait");
        clock.advance(1);
        let probe = breaker.acquire().expect("the probe goes through at the end of the wait");
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        assert!(breaker.acquire().is_none(), "only one probe at a time");
        probe.success();
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert!(breaker.acquire().is_some());
    }

    #[test]
    fn a_failed_probe_reopens_for_a_full_wait() {
        let (breaker, clock) = breaker(1, 100);
        fail(&breaker);
        clock.advance(100);
        breaker.acquire().unwrap().failure();
        assert_eq!(breaker.state(), BreakerState::Open);
        clock.advance(99);
        assert!(breaker.acquire().is_none());
        clock.advance(1);
        assert!(breaker.acquire().is_some());
    }

    #[test]
    fn a_cancelled_probe_counts_as_a_failure() {
        let (breaker, clock) = breaker(1, 100);
        fail(&breaker);
        clock.advance(100);
        drop(breaker.acquire().expect("the probe"));
        assert_eq!(breaker.state(), BreakerState::Open);
        clock.advance(100);
        assert!(breaker.acquire().is_some(), "the circuit recovers instead of waiting for a lost probe");
    }

    #[test]
    fn a_threshold_of_zero_opens_on_the_first_failure() {
        let (breaker, _) = breaker(0, 100);
        fail(&breaker);
        assert_eq!(breaker.state(), BreakerState::Open);
    }
}
