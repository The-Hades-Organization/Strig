//! How the client reaches the server. The built-in transport speaks plain HTTP/1.1; for TLS or a
//! proxy, implement [`Transport`] over the stack you already use.

use std::error::Error;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::{Request, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::config::TIMEOUT_HEADER;

/// The status and body of an answer, whatever the status is.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RawResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl RawResponse {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }
}

/// The call could not be made or its answer could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    #[error("could not reach the server")]
    Unreachable(#[source] Box<dyn Error + Send + Sync>),
}

impl TransportError {
    pub fn unreachable(cause: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self::Unreachable(cause.into())
    }
}

/// POSTs a JSON body to a path of the server.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends `body` to `path` and returns whatever status came back. `timeout` is the deadline
    /// the client enforces; send it to the server so it stops working when the client gives up.
    ///
    /// # Errors
    ///
    /// [`TransportError::Unreachable`] when there is no answer to return.
    async fn post(&self, path: &str, timeout: Duration, body: Vec<u8>) -> Result<RawResponse, TransportError>;
}

/// The deadline header value: whole milliseconds, never zero, which the server refuses.
pub(crate) fn timeout_header(timeout: Duration) -> String {
    timeout.as_millis().max(1).to_string()
}

/// Plain HTTP/1.1 over TCP, with a cap on the size of the answer it reads.
pub struct HttpTransport {
    client: HyperClient<HttpConnector, Full<Bytes>>,
    base_url: String,
    max_response_bytes: usize,
}

impl HttpTransport {
    /// Largest answer the transport reads.
    pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

    /// `base_url` is the scheme and authority, such as `http://127.0.0.1:8080`.
    pub fn new(base_url: impl Into<String>) -> Self {
        let mut base_url = base_url.into();
        while base_url.ends_with('/') {
            base_url.pop();
        }
        Self {
            client: HyperClient::builder(TokioExecutor::new()).build(HttpConnector::new()),
            base_url,
            max_response_bytes: Self::DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    #[must_use]
    pub fn with_max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn post(&self, path: &str, timeout: Duration, body: Vec<u8>) -> Result<RawResponse, TransportError> {
        let request = Request::post(format!("{}{path}", self.base_url))
            .header(header::CONTENT_TYPE, "application/json")
            .header(TIMEOUT_HEADER, timeout_header(timeout))
            .body(Full::new(Bytes::from(body)))
            .map_err(TransportError::unreachable)?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(TransportError::unreachable)?;
        let status = response.status().as_u16();
        let body = Limited::new(response.into_body(), self.max_response_bytes)
            .collect()
            .await
            .map_err(TransportError::unreachable)?
            .to_bytes()
            .to_vec();
        Ok(RawResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_under_one_millisecond_is_sent_as_one() {
        assert_eq!(timeout_header(Duration::ZERO), "1");
        assert_eq!(timeout_header(Duration::from_micros(400)), "1");
        assert_eq!(timeout_header(Duration::from_millis(1)), "1");
        assert_eq!(timeout_header(Duration::from_millis(250)), "250");
    }
}
