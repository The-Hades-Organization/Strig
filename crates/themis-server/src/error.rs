//! The error body, with fixed codes and generic messages.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use themis::QueryError;

/// Stable error codes. A code never changes meaning; new ones are added, so match with a
/// wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// 400: the body is not JSON.
    MalformedJson,
    /// 400: valid JSON that does not fit the route's schema, or a bad deadline header.
    InvalidRequest,
    /// 400: more checks than `max_batch`.
    BatchTooLarge,
    /// 400: more candidate resources than `max_resources`.
    TooManyResources,
    /// 413: the body is over the limit.
    BodyTooLarge,
    /// 415: the body is not `application/json`.
    UnsupportedMediaType,
    /// 404: no such route.
    NotFound,
    /// 405: the route does not take this method.
    MethodNotAllowed,
    /// 503: the policy or the grants could not be loaded.
    SourceUnavailable,
    /// 503: the query went past a `QueryLimits` ceiling.
    QueryLimitExceeded,
    /// 503: a relation chain went deeper than the engine allows and a deny could not be read.
    RelationDepthExceeded,
    /// 503: the deadline passed before the answer was ready.
    DeadlineExceeded,
    /// 503: the server clock has no usable instant.
    ClockUnavailable,
    /// 503: anything else that went wrong inside the server.
    Internal,
}

impl ErrorCode {
    pub fn status(self) -> StatusCode {
        match self {
            ErrorCode::MalformedJson
            | ErrorCode::InvalidRequest
            | ErrorCode::BatchTooLarge
            | ErrorCode::TooManyResources => StatusCode::BAD_REQUEST,
            ErrorCode::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ErrorCode::SourceUnavailable
            | ErrorCode::QueryLimitExceeded
            | ErrorCode::RelationDepthExceeded
            | ErrorCode::DeadlineExceeded
            | ErrorCode::ClockUnavailable
            | ErrorCode::Internal => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The message that goes with the code. It is fixed on purpose: names of tables, paths and
    /// driver messages stay in the server log.
    pub fn message(self) -> &'static str {
        match self {
            ErrorCode::MalformedJson => "the request body is not valid JSON",
            ErrorCode::InvalidRequest => "the request does not match the schema of this route",
            ErrorCode::BatchTooLarge => "the batch has more checks than the server accepts",
            ErrorCode::TooManyResources => "the request names more resources than the server accepts",
            ErrorCode::BodyTooLarge => "the request body is larger than the server accepts",
            ErrorCode::UnsupportedMediaType => "the request body must be application/json",
            ErrorCode::NotFound => "no such route",
            ErrorCode::MethodNotAllowed => "method not allowed on this route",
            ErrorCode::SourceUnavailable => "the grant source is unavailable; access is denied",
            ErrorCode::QueryLimitExceeded => "the query is over the server limits; access is denied",
            ErrorCode::RelationDepthExceeded => "a relation chain is too deep to read; access is denied",
            ErrorCode::DeadlineExceeded => "the deadline passed before an answer was ready; access is denied",
            ErrorCode::ClockUnavailable => "the server clock is unavailable; access is denied",
            ErrorCode::Internal => "internal error; access is denied",
        }
    }

    /// Whether the code is one of the fail-closed answers (status 503).
    pub fn is_fail_closed(self) -> bool {
        self.status() == StatusCode::SERVICE_UNAVAILABLE
    }
}

/// `{"error": {"code": "...", "message": "..."}}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub message: String,
}

impl ErrorBody {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            error: ErrorDetail {
                code,
                message: code.message().to_string(),
            },
        }
    }
}

/// An error that becomes the stable body and its status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiError {
    pub code: ErrorCode,
}

impl ApiError {
    pub fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

impl From<QueryError> for ApiError {
    fn from(error: QueryError) -> Self {
        // The detail (the limit, the grant id) stays in the log.
        tracing::warn!(error = %error, "reverse query failed closed");
        match error {
            QueryError::LimitExceeded { .. } => ApiError::new(ErrorCode::QueryLimitExceeded),
            QueryError::RelationDepthExceeded { .. } => ApiError::new(ErrorCode::RelationDepthExceeded),
            // `UnknownSubject` cannot come out of the routes (they never load a subject by
            // reference); the enum is non-exhaustive, so anything else is an internal error.
            _ => ApiError::new(ErrorCode::Internal),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.code.is_fail_closed() {
            tracing::warn!(code = ?self.code, "answering 503, access denied");
        }
        (self.code.status(), Json(ErrorBody::new(self.code))).into_response()
    }
}
