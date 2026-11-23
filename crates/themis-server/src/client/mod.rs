//! The Rust client: a timeout per call, a circuit breaker and answers that fail closed.
//!
//! [`Client::check`] never returns an allow it did not get from the server. A network failure, a
//! timeout, a 5xx, an answer it cannot read or an open circuit all come back as
//! [`ClientDecision::Denied`] with the typed [`Failure`] that caused it.

mod breaker;
mod transport;

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use themis::{Decision, Effect};

pub use breaker::{BreakerConfig, BreakerState, CircuitBreaker, Permit};
pub use transport::{HttpTransport, RawResponse, Transport, TransportError};

use crate::clock::{Clock, MonotonicClock};
use crate::error::{ErrorBody, ErrorCode};
use crate::wire::{
    AccessRequest, AccessResponse, BatchResponse, CheckRequest, CheckResponse, ListRequest, ListResponse, WhoRequest,
    WhoResponse,
};

/// Why a call produced no answer from the server.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Failure {
    /// The circuit is open: the call was not even made.
    #[error("the circuit breaker is open")]
    CircuitOpen,
    /// The server did not answer within the call's timeout.
    #[error("the call timed out")]
    Timeout,
    /// The connection failed or the answer could not be read.
    #[error("the server could not be reached")]
    Unreachable,
    /// The server answered 5xx (the fail-closed 503 included).
    #[error("the server failed with status {status}")]
    Server { status: u16, code: Option<ErrorCode> },
    /// The server refused the request (4xx): a bug in the caller, not an outage.
    #[error("the server rejected the request with status {status}")]
    Rejected { status: u16, code: Option<ErrorCode> },
    /// A 2xx answer that is not what the route promises.
    #[error("the answer of the server could not be understood")]
    InvalidResponse,
    /// The request could not be turned into JSON.
    #[error("the request could not be encoded")]
    Encode,
}

/// The outcome of a check: what the server decided, or the deny the client made up for it.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientDecision {
    /// The server's answer, allow or deny.
    Remote(CheckResponse),
    /// No answer: the client denies, and says why.
    Denied(Failure),
}

impl ClientDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, ClientDecision::Remote(answer) if answer.decision.is_allowed())
    }

    pub fn effect(&self) -> Effect {
        if self.is_allowed() { Effect::Allow } else { Effect::Deny }
    }

    /// The server's decision, when there was one.
    pub fn decision(&self) -> Option<&Decision> {
        match self {
            ClientDecision::Remote(answer) => Some(&answer.decision),
            ClientDecision::Denied(_) => None,
        }
    }

    /// Why the client denied without the server, when it did.
    pub fn failure(&self) -> Option<&Failure> {
        match self {
            ClientDecision::Remote(_) => None,
            ClientDecision::Denied(failure) => Some(failure),
        }
    }
}

/// Settings of a [`Client`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ClientConfig {
    /// Deadline of every call. It is also sent to the server.
    pub timeout: Duration,
    pub breaker: BreakerConfig,
}

impl ClientConfig {
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_breaker(mut self, breaker: BreakerConfig) -> Self {
        self.breaker = breaker;
        self
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            breaker: BreakerConfig::default(),
        }
    }
}

/// Calls a Themis decision server.
pub struct Client {
    transport: Arc<dyn Transport>,
    breaker: CircuitBreaker,
    timeout: Duration,
}

impl Client {
    /// A client over plain HTTP to `base_url` (`http://host:port`).
    pub fn http(base_url: impl Into<String>, config: ClientConfig) -> Self {
        Self::new(Arc::new(HttpTransport::new(base_url)), config)
    }

    /// A client over any [`Transport`], with a monotonic clock for the breaker.
    pub fn new(transport: Arc<dyn Transport>, config: ClientConfig) -> Self {
        Self::with_clock(transport, config, Arc::new(MonotonicClock::new()))
    }

    /// Like [`Client::new`], with the clock the breaker reads its timers from.
    pub fn with_clock(transport: Arc<dyn Transport>, config: ClientConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            transport,
            breaker: CircuitBreaker::new(config.breaker, clock),
            timeout: config.timeout,
        }
    }

    pub fn breaker_state(&self) -> BreakerState {
        self.breaker.state()
    }

    /// One check. Any failure is a [`ClientDecision::Denied`].
    pub async fn check(&self, request: &CheckRequest) -> ClientDecision {
        match self.call::<CheckResponse>("/v1/check", request).await {
            Ok(answer) => ClientDecision::Remote(answer),
            Err(failure) => ClientDecision::Denied(failure),
        }
    }

    /// `requests.len()` checks in one call, answered in the same order. If the call fails, or the
    /// server answers a different number of results, every check is denied with the same cause.
    pub async fn check_batch(&self, requests: &[CheckRequest]) -> Vec<ClientDecision> {
        if requests.is_empty() {
            return Vec::new();
        }
        #[derive(Serialize)]
        struct Body<'a> {
            checks: &'a [CheckRequest],
        }
        let outcome = match self
            .call::<BatchResponse>("/v1/check/batch", &Body { checks: requests })
            .await
        {
            Ok(answer) if answer.results.len() == requests.len() => Ok(answer.results),
            Ok(_) => Err(Failure::InvalidResponse),
            Err(failure) => Err(failure),
        };
        match outcome {
            Ok(results) => results.into_iter().map(ClientDecision::Remote).collect(),
            Err(failure) => requests.iter().map(|_| ClientDecision::Denied(failure.clone())).collect(),
        }
    }

    /// The listing filter of a subject. There is no deny to fall back on: a failure is an error,
    /// and the caller must not list anything.
    ///
    /// # Errors
    ///
    /// The [`Failure`] of the call.
    pub async fn list(&self, request: &ListRequest) -> Result<ListResponse, Failure> {
        self.call("/v1/list", request).await
    }

    /// Who holds a permission (`who_can`, `who_can_on`).
    ///
    /// # Errors
    ///
    /// The [`Failure`] of the call.
    pub async fn who(&self, request: &WhoRequest) -> Result<WhoResponse, Failure> {
        self.call("/v1/who", request).await
    }

    /// Who reaches a resource, and with what.
    ///
    /// # Errors
    ///
    /// The [`Failure`] of the call.
    pub async fn access(&self, request: &AccessRequest) -> Result<AccessResponse, Failure> {
        self.call("/v1/access", request).await
    }

    async fn call<T: DeserializeOwned>(&self, path: &str, body: &impl Serialize) -> Result<T, Failure> {
        let body = serde_json::to_vec(body).map_err(|error| {
            tracing::error!(error = %error, "could not encode the request");
            Failure::Encode
        })?;
        let permit = self.breaker.acquire().ok_or(Failure::CircuitOpen)?;
        let raw = match tokio::time::timeout(self.timeout, self.transport.post(path, self.timeout, body)).await {
            Err(_) => {
                permit.failure();
                return Err(Failure::Timeout);
            }
            Ok(Err(error)) => {
                tracing::warn!(error = ?error, path, "the decision server could not be reached");
                permit.failure();
                return Err(Failure::Unreachable);
            }
            Ok(Ok(raw)) => raw,
        };
        let code = || serde_json::from_slice::<ErrorBody>(&raw.body).ok().map(|body| body.error.code);
        match raw.status {
            200..=299 => match serde_json::from_slice(&raw.body) {
                Ok(answer) => {
                    permit.success();
                    Ok(answer)
                }
                Err(error) => {
                    tracing::warn!(error = %error, path, "the decision server sent an unreadable answer");
                    permit.failure();
                    Err(Failure::InvalidResponse)
                }
            },
            status if status >= 500 => {
                permit.failure();
                Err(Failure::Server { status, code: code() })
            }
            status => {
                // The server is up and said no to this request: that is not an outage.
                permit.success();
                Err(Failure::Rejected { status, code: code() })
            }
        }
    }
}
