//! A three-state circuit breaker with an injected clock.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

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
enum Phase {
    Closed {
        failures: u32,
    },
    /// `since_ms` is the injected clock at the moment of opening, if it answered; `since` is the
    /// local monotonic reading, the fallback to measure the wait when the clock has no answer.
    Open {
        since_ms: Option<u64>,
        since: Instant,
    },
    /// The one probe is in flight.
    HalfOpen,
}

/// The phase and the generation: a counter that goes up at every change of phase, so a permit
/// settles only the phase it was issued in.
#[derive(Debug, Clone, Copy)]
struct Inner {
    phase: Phase,
    generation: u64,
}

impl Inner {
    fn enter(&mut self, phase: Phase) {
        self.phase = phase;
        self.generation = self.generation.wrapping_add(1);
    }
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
            inner: Mutex::new(Inner {
                phase: Phase::Closed { failures: 0 },
                generation: 0,
            }),
        }
    }

    pub fn state(&self) -> BreakerState {
        match self.lock().phase {
            Phase::Closed { .. } => BreakerState::Closed,
            Phase::Open { .. } => BreakerState::Open,
            Phase::HalfOpen => BreakerState::HalfOpen,
        }
    }

    /// Asks to make a call. `None` means the circuit refuses it. The permit must be settled with
    /// [`Permit::success`] or [`Permit::failure`]; a permit dropped without either (the call was
    /// cancelled) counts as a failure, so a lost probe cannot leave the circuit half-open forever.
    ///
    /// A permit settles only the state it was issued in. One that outlives its state (a slow call
    /// that ends after the circuit opened, or after the probe went out) changes nothing.
    pub fn acquire(&self) -> Option<Permit<'_>> {
        let mut inner = self.lock();
        let allowed = match inner.phase {
            Phase::Closed { .. } => true,
            Phase::Open { since_ms, since } if self.waited(since_ms, since) => {
                inner.enter(Phase::HalfOpen);
                true
            }
            Phase::Open { .. } | Phase::HalfOpen => false,
        };
        let generation = inner.generation;
        drop(inner);
        allowed.then_some(Permit {
            breaker: self,
            generation,
            settled: false,
        })
    }

    fn wait_ms(&self) -> u64 {
        u64::try_from(self.config.open_for.as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether the wait of an open circuit is over. It is measured on the injected clock; when the
    /// clock has no answer (now, or when the circuit opened) the local monotonic reading takes its
    /// place, so a dead clock makes the circuit open and try again later instead of staying open
    /// for good. Calls stay fail-closed either way: a probe that fails reopens it.
    fn waited(&self, since_ms: Option<u64>, since: Instant) -> bool {
        let elapsed = match (since_ms, self.clock.now_ms()) {
            (Some(opened), Some(now)) => now.saturating_sub(opened),
            _ => u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        elapsed >= self.wait_ms()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // The state is one small `Copy` value, so a poisoned lock holds nothing half-written.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record_success(&self, generation: u64) {
        let mut inner = self.lock();
        if inner.generation != generation {
            return;
        }
        match inner.phase {
            Phase::Closed { .. } => inner.phase = Phase::Closed { failures: 0 },
            Phase::HalfOpen => inner.enter(Phase::Closed { failures: 0 }),
            // Same generation but open cannot be: opening bumps it.
            Phase::Open { .. } => {}
        }
    }

    fn record_failure(&self, generation: u64) {
        let mut inner = self.lock();
        if inner.generation != generation {
            return;
        }
        let opened = Phase::Open {
            since_ms: self.clock.now_ms(),
            since: Instant::now(),
        };
        match inner.phase {
            Phase::Closed { failures } if failures.saturating_add(1) >= self.config.failure_threshold => {
                inner.enter(opened);
            }
            Phase::Closed { failures } => {
                inner.phase = Phase::Closed {
                    failures: failures.saturating_add(1),
                };
            }
            Phase::HalfOpen => inner.enter(opened),
            Phase::Open { .. } => {}
        }
    }
}

/// Permission for one call, settled with its outcome.
#[must_use = "settle the permit with success() or failure()"]
pub struct Permit<'a> {
    breaker: &'a CircuitBreaker,
    generation: u64,
    settled: bool,
}

impl Permit<'_> {
    pub fn success(mut self) {
        self.settled = true;
        self.breaker.record_success(self.generation);
    }

    pub fn failure(mut self) {
        self.settled = true;
        self.breaker.record_failure(self.generation);
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.breaker.record_failure(self.generation);
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
        let probe = breaker
            .acquire()
            .expect("the probe goes through at the end of the wait");
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
        assert!(
            breaker.acquire().is_some(),
            "the circuit recovers instead of waiting for a lost probe"
        );
    }

    #[test]
    fn a_threshold_of_zero_opens_on_the_first_failure() {
        let (breaker, _) = breaker(0, 100);
        fail(&breaker);
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    #[test]
    fn a_late_success_from_before_the_circuit_opened_does_not_close_it() {
        let (breaker, _) = breaker(2, 100);
        let slow = breaker.acquire().expect("a call that will take long");
        fail(&breaker);
        fail(&breaker);
        assert_eq!(breaker.state(), BreakerState::Open);
        slow.success();
        assert_eq!(breaker.state(), BreakerState::Open, "the wait is not skipped");
    }

    #[test]
    fn a_late_success_does_not_settle_the_probe() {
        let (breaker, clock) = breaker(1, 100);
        let slow = breaker.acquire().expect("a call that will take long");
        fail(&breaker);
        clock.advance(100);
        let probe = breaker.acquire().expect("the probe");
        slow.success();
        assert_eq!(breaker.state(), BreakerState::HalfOpen, "only the probe closes it");
        probe.failure();
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    #[test]
    fn a_late_failure_does_not_reopen_a_circuit_whose_probe_is_in_flight() {
        let (breaker, clock) = breaker(2, 100);
        let slow = breaker.acquire().expect("a call that will take long");
        fail(&breaker);
        fail(&breaker);
        clock.advance(100);
        let probe = breaker.acquire().expect("the probe");
        slow.failure();
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        probe.success();
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[test]
    fn a_dropped_stale_permit_changes_nothing() {
        let (breaker, _) = breaker(1, 100);
        let slow = breaker.acquire().expect("a call that will take long");
        fail(&breaker);
        drop(slow);
        assert_eq!(breaker.state(), BreakerState::Open);
        let (other, clock) = self::breaker(1, 100);
        fail(&other);
        clock.advance(100);
        let probe = other.acquire().expect("the probe");
        let stale = other.acquire();
        assert!(stale.is_none());
        probe.success();
        assert_eq!(other.state(), BreakerState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn a_clock_with_no_answer_opens_and_then_tries_again() {
        use crate::clock::BrokenClock;
        let config = BreakerConfig::default()
            .with_failure_threshold(1)
            .with_open_for(Duration::from_secs(30));
        let breaker = CircuitBreaker::new(config, Arc::new(BrokenClock));
        fail(&breaker);
        assert_eq!(breaker.state(), BreakerState::Open);
        assert!(breaker.acquire().is_none(), "fail-closed inside the wait");
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(breaker.acquire().is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        let probe = breaker.acquire().expect("the wait ends even without a clock");
        probe.failure();
        assert_eq!(breaker.state(), BreakerState::Open, "a failed probe reopens it");
        assert!(breaker.acquire().is_none());
    }
}
