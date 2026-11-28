//! Spans and metrics of the engine (feature `tracing`).
//!
//! Every entry point here has a twin with the same signature that only runs the closure, so the call
//! sites carry no `cfg` and, with the feature off, compile to the plain call. Nothing in this module
//! does IO: `tracing` and `metrics` are facades, and without a subscriber or a recorder installed
//! they cost one atomic load.
//!
//! Labels carry only what the application declares in code: permission (when the catalog knows it),
//! effect, reason kind, invariant name, step, outcome. Never a subject id, a resource id or an
//! attribute value.

use crate::decision::{Decision, Request};
use crate::governance::Violation;

#[cfg(feature = "tracing")]
mod on {
    use super::*;
    use crate::decision::Reason;
    use crate::grant::Effect;

    pub const DECISION_DURATION: &str = "strig_decision_duration_seconds";
    pub const DECISIONS: &str = "strig_decisions_total";
    pub const MUTATIONS: &str = "strig_mutations_total";
    pub const VIOLATIONS: &str = "strig_mutation_violations_total";
    pub const APPROVALS: &str = "strig_approvals_total";
    pub const QUERY_DURATION: &str = "strig_query_duration_seconds";

    /// `std::time::Instant` panics on `wasm32-unknown-unknown`, so the duration is not measured there.
    #[cfg(not(target_arch = "wasm32"))]
    pub struct Timer(std::time::Instant);
    #[cfg(target_arch = "wasm32")]
    pub struct Timer;

    impl Timer {
        pub fn start() -> Self {
            #[cfg(not(target_arch = "wasm32"))]
            return Self(std::time::Instant::now());
            #[cfg(target_arch = "wasm32")]
            Self
        }

        pub fn record(self, name: &'static str, operation: &'static str) {
            #[cfg(not(target_arch = "wasm32"))]
            metrics::histogram!(name, "operation" => operation).record(self.0.elapsed().as_secs_f64());
            #[cfg(target_arch = "wasm32")]
            let _ = (name, operation);
        }
    }

    thread_local! {
        static DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    /// Marks an observed operation. Only the outermost one on a thread feeds the metrics: a decision an
    /// invariant makes while governance judges a change is part of that change, not a decision the
    /// application asked for. Spans nest either way.
    pub struct Scope {
        outermost: bool,
    }

    impl Scope {
        pub fn enter() -> Self {
            let outermost = DEPTH.with(|depth| {
                depth.set(depth.get() + 1);
                depth.get() == 1
            });
            Self { outermost }
        }

        pub fn outermost(&self) -> bool {
            self.outermost
        }
    }

    impl Drop for Scope {
        fn drop(&mut self) {
            DEPTH.with(|depth| depth.set(depth.get() - 1));
        }
    }

    pub fn reason_kind(reason: &Reason) -> &'static str {
        match reason {
            Reason::Override { .. } => "override",
            Reason::Grant { .. } => "grant",
            Reason::NoApplicableGrant => "no_applicable_grant",
            Reason::UnknownPermission => "unknown_permission",
            Reason::MissingPrerequisite { .. } => "missing_prerequisite",
        }
    }

    pub fn effect_label(effect: Effect) -> &'static str {
        match effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
        }
    }

    pub fn count_decision(request: &Request<'_>, decision: &Decision, operation: &'static str) {
        let permission = match decision.reason {
            Reason::UnknownPermission => "unknown".to_string(),
            _ => request.permission.to_string(),
        };
        metrics::counter!(
            DECISIONS,
            "operation" => operation,
            "effect" => effect_label(decision.effect),
            "reason" => reason_kind(&decision.reason),
            "permission" => permission,
        )
        .increment(1);
    }

    pub fn count_violations(violations: &[Violation]) {
        for violation in violations {
            metrics::counter!(VIOLATIONS, "invariant" => violation.invariant.clone()).increment(1);
        }
    }
}

#[cfg(feature = "tracing")]
pub(crate) use on::{APPROVALS, MUTATIONS, QUERY_DURATION, Scope, Timer, count_violations, effect_label, reason_kind};

/// Runs a decision under the `strig.decide` / `strig.explain` span and counts it.
#[cfg(feature = "tracing")]
pub(crate) fn decision<T>(
    operation: &'static str,
    request: &Request<'_>,
    run: impl FnOnce() -> T,
    decision_of: impl Fn(&T) -> &Decision,
) -> T {
    let span = tracing::debug_span!(
        "strig.decision",
        operation,
        permission = request.permission,
        effect = tracing::field::Empty,
        reason = tracing::field::Empty,
    );
    let scope = Scope::enter();
    let timer = Timer::start();
    let result = span.in_scope(run);
    let decided = decision_of(&result);
    span.record("effect", effect_label(decided.effect));
    span.record("reason", reason_kind(&decided.reason));
    if scope.outermost() {
        timer.record(on::DECISION_DURATION, operation);
        on::count_decision(request, decided, operation);
    }
    result
}

#[cfg(not(feature = "tracing"))]
#[inline(always)]
pub(crate) fn decision<T>(
    _operation: &'static str,
    _request: &Request<'_>,
    run: impl FnOnce() -> T,
    _decision_of: impl Fn(&T) -> &Decision,
) -> T {
    run()
}

/// Runs a reverse query (`list`, `who_can`) under its span and times it.
#[cfg(feature = "tracing")]
pub(crate) fn query<T>(operation: &'static str, permission: &str, kind: Option<&str>, run: impl FnOnce() -> T) -> T {
    let span = tracing::debug_span!("strig.query", operation, permission, kind);
    let scope = Scope::enter();
    let timer = Timer::start();
    let result = span.in_scope(run);
    if scope.outermost() {
        timer.record(QUERY_DURATION, operation);
    }
    result
}

#[cfg(not(feature = "tracing"))]
#[inline(always)]
pub(crate) fn query<T>(_operation: &'static str, _permission: &str, _kind: Option<&str>, run: impl FnOnce() -> T) -> T {
    run()
}

/// Runs a governed change under the `strig.governance.apply` span and counts applied and refused
/// changes, and the invariants that refused them.
#[cfg(feature = "tracing")]
pub(crate) fn mutation<R>(run: impl FnOnce() -> R, violations_of: impl Fn(&R) -> Option<&[Violation]>) -> R {
    let span = tracing::info_span!("strig.governance.apply", outcome = tracing::field::Empty);
    let scope = Scope::enter();
    let result = span.in_scope(run);
    let violations = violations_of(&result);
    span.record("outcome", if violations.is_some() { "refused" } else { "applied" });
    if scope.outermost() {
        match violations {
            None => metrics::counter!(MUTATIONS, "outcome" => "applied").increment(1),
            Some(violations) => {
                metrics::counter!(MUTATIONS, "outcome" => "refused").increment(1);
                count_violations(violations);
            }
        }
    }
    result
}

#[cfg(not(feature = "tracing"))]
#[inline(always)]
pub(crate) fn mutation<R>(run: impl FnOnce() -> R, _violations_of: impl Fn(&R) -> Option<&[Violation]>) -> R {
    run()
}

/// Runs a step of the approval flow (`propose`, `approve`, `reject`, `expire`) under its span and
/// counts how it ended.
#[cfg(feature = "tracing")]
pub(crate) fn approval<T>(
    step: &'static str,
    run: impl FnOnce() -> Result<T, crate::pending::ApprovalError>,
) -> Result<T, crate::pending::ApprovalError> {
    use crate::pending::ApprovalError;
    let span = tracing::info_span!("strig.approval", step, outcome = tracing::field::Empty);
    let scope = Scope::enter();
    let result = span.in_scope(run);
    let outcome = match &result {
        Ok(_) => "ok",
        Err(ApprovalError::Refused(_)) => "refused",
        Err(ApprovalError::Expired(_)) => "expired",
        Err(ApprovalError::Store(_)) => "store_error",
    };
    span.record("outcome", outcome);
    if scope.outermost() {
        if let Err(ApprovalError::Refused(violations)) = &result {
            count_violations(violations);
        }
        metrics::counter!(APPROVALS, "step" => step, "outcome" => outcome).increment(1);
    }
    result
}

#[cfg(not(feature = "tracing"))]
#[inline(always)]
pub(crate) fn approval<T>(
    _step: &'static str,
    run: impl FnOnce() -> Result<T, crate::pending::ApprovalError>,
) -> Result<T, crate::pending::ApprovalError> {
    run()
}

/// Metrics and events of the audit trail: where each record ended up, the depth of the retry queue,
/// failed writes and dropped records.
#[cfg(all(feature = "tracing", feature = "audit"))]
pub(crate) mod audit {
    use crate::audit::AuditStatus;

    pub const WRITES: &str = "strig_audit_writes_total";
    pub const PENDING: &str = "strig_audit_pending";
    pub const FAILURES: &str = "strig_audit_write_failures_total";
    pub const DROPPED: &str = "strig_audit_dropped_total";

    pub fn status(status: AuditStatus) {
        let label = match status {
            AuditStatus::Written => "written",
            AuditStatus::Pending => "pending",
            AuditStatus::Dropped => {
                metrics::counter!(DROPPED).increment(1);
                tracing::warn!("audit record dropped: the retry queue is full");
                "dropped"
            }
        };
        metrics::counter!(WRITES, "status" => label).increment(1);
    }

    pub fn refused() {
        metrics::counter!(WRITES, "status" => "refused").increment(1);
        tracing::warn!("audit record refused: the sink failed in closed mode");
    }

    pub fn write_failed() {
        metrics::counter!(FAILURES).increment(1);
        tracing::warn!("audit sink write failed; the record waits for a retry");
    }

    pub fn retried(written: u64) {
        if written > 0 {
            tracing::info!(written, "audit retry queue drained records");
        }
    }

    pub fn depth(pending: usize) {
        metrics::gauge!(PENDING).set(pending as f64);
    }
}
