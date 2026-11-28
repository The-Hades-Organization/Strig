//! Spans and metrics of the hub, the relay and the sessions (feature `tracing`).
//!
//! Labels carry the kind of the change and the name of the transport, never a subject, a scope or a
//! change id.

#[cfg(feature = "tracing")]
mod on {
    use crate::change::{Change, ChangeKind};

    pub const CHANGES: &str = "strig_sync_changes_total";
    pub const PUBLISH_ERRORS: &str = "strig_sync_publish_errors_total";
    pub const SESSIONS_OPEN: &str = "strig_sync_sessions_open";
    pub const SESSIONS_OPENED: &str = "strig_sync_sessions_opened_total";
    pub const RESYNCS: &str = "strig_sync_resyncs_total";
    pub const TRANSPORT_RECONNECTS: &str = "strig_sync_transport_reconnects_total";
    pub const TRANSPORT_FAILURES: &str = "strig_sync_transport_failures_total";

    pub fn kind(change: &Change) -> &'static str {
        match change.kind {
            ChangeKind::Grants => "grants",
            ChangeKind::Tuples => "tuples",
            ChangeKind::Roles => "roles",
            ChangeKind::Catalog => "catalog",
            ChangeKind::Custom => "custom",
            ChangeKind::Resync => "resync",
        }
    }

    pub fn change(change: &Change, direction: &'static str) {
        metrics::counter!(CHANGES, "kind" => kind(change), "direction" => direction).increment(1);
    }

    pub fn publish_failed(transport: Option<&str>) {
        metrics::counter!(PUBLISH_ERRORS, "transport" => transport.unwrap_or("none").to_string()).increment(1);
        tracing::warn!("publishing a change on the transport failed");
    }

    pub fn resync(reason: &'static str) {
        metrics::counter!(RESYNCS, "reason" => reason).increment(1);
    }

    pub fn transport_reconnected(transport: &str) {
        metrics::counter!(TRANSPORT_RECONNECTS, "transport" => transport.to_string()).increment(1);
        tracing::info!(transport, "transport reconnected, emitting a resync");
    }

    pub fn transport_failed(transport: &str, stage: &'static str) {
        metrics::counter!(TRANSPORT_FAILURES, "transport" => transport.to_string(), "stage" => stage).increment(1);
        tracing::warn!(transport, stage, "transport failure, the relay will retry");
    }

    /// Counts a session as open until it drops.
    pub struct SessionGuard;

    impl SessionGuard {
        pub fn open() -> Self {
            metrics::counter!(SESSIONS_OPENED).increment(1);
            metrics::gauge!(SESSIONS_OPEN).increment(1.0);
            Self
        }
    }

    impl Drop for SessionGuard {
        fn drop(&mut self) {
            metrics::gauge!(SESSIONS_OPEN).decrement(1.0);
        }
    }
}

#[cfg(feature = "tracing")]
pub(crate) use on::*;
