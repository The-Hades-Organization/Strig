//! Metrics of the decision server and its client (feature `tracing`).
//!
//! Labels are the route (a fixed set), the status or outcome, the stable error code and the breaker
//! phase. Never a subject, a resource, a permission asked for or a body.

#[cfg(feature = "tracing")]
pub(crate) mod on {
    pub const REQUESTS: &str = "strig_server_requests_total";
    pub const REQUEST_DURATION: &str = "strig_server_request_duration_seconds";
    pub const ERRORS: &str = "strig_server_errors_total";
    pub const CALLS: &str = "strig_client_calls_total";
    pub const CALL_DURATION: &str = "strig_client_call_duration_seconds";
    pub const BREAKER_TRANSITIONS: &str = "strig_client_breaker_transitions_total";
    pub const BREAKER_STATE: &str = "strig_client_breaker_state";

    pub fn error(code: &str) {
        metrics::counter!(ERRORS, "code" => code.to_string()).increment(1);
    }

    pub fn breaker(to: &'static str, level: f64) {
        metrics::counter!(BREAKER_TRANSITIONS, "to" => to).increment(1);
        metrics::gauge!(BREAKER_STATE).set(level);
        tracing::info!(to, "circuit breaker changed phase");
    }
}

#[cfg(feature = "tracing")]
pub(crate) use on::*;

#[cfg(feature = "tracing")]
pub(crate) mod http {
    use std::time::Instant;

    use axum::extract::{MatchedPath, Request};
    use axum::middleware::Next;
    use axum::response::Response;
    use tracing::Instrument;

    /// One span and the request metrics for each decision route.
    pub async fn observe(request: Request, next: Next) -> Response {
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map_or("unmatched", MatchedPath::as_str)
            .to_string();
        let span = tracing::info_span!("strig.server.request", route = %route, status = tracing::field::Empty);
        let started = Instant::now();
        let response = next.run(request).instrument(span.clone()).await;
        let status = response.status().as_u16();
        span.record("status", status);
        metrics::counter!(super::on::REQUESTS, "route" => route.clone(), "status" => status.to_string()).increment(1);
        metrics::histogram!(super::on::REQUEST_DURATION, "route" => route).record(started.elapsed().as_secs_f64());
        response
    }
}
