//! Envoy External Authorization (`envoy.service.auth.v3.Authorization/Check`, gRPC), so a service
//! mesh or a gateway built on Envoy asks Strig whether a request may pass.
//!
//! [`DecisionServer::envoy_service`](crate::DecisionServer::envoy_service) builds the service over
//! the same [`DecisionSource`](crate::DecisionSource), clock and limits as the HTTP routes. An
//! [`EnvoyConfig`] says how a `CheckRequest` becomes a decision: where the subject comes from, which
//! permission each method and path asks for and which resource it asks it on. The answer is `OK`
//! on an allow and `PERMISSION_DENIED` with HTTP 403 on everything else: a route with no rule, a
//! request without a subject, a source that is down, a deadline that passed. `API.md` has the
//! contract and an `envoy.yaml`.

mod check;
mod proto;
mod route;
mod service;

use std::fmt;
use std::sync::Arc;

use axum::http::HeaderName;

use crate::authzen::PathResolver;

pub use proto::{
    AttributeContext, CheckRequest, CheckResponse, DeniedHttpResponse, HeaderValue, HeaderValueOption, HttpRequest,
    HttpStatus, Metadata, OkHttpResponse, Request, Status, check_response,
};
pub use route::{ResourceTemplate, RouteRule};
pub use service::EnvoyService;

pub(crate) use check::Verdict;
use route::RouteTable;

/// The response header that carries a fixed code for a denial. It is sent only when
/// [`EnvoyConfig::with_reasons`] is on.
pub const REASON_HEADER: &str = "x-strig-reason";

/// Why an [`EnvoyConfig`] value was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvoyConfigError {
    /// A path pattern must start with `/`; its segments are literals, `{name}`, `*`, and a last
    /// `**`. Parameter names are not repeated.
    #[error("the path pattern is not valid")]
    InvalidPattern,
    /// Methods are `*` or a comma-separated list of names such as `GET,HEAD`.
    #[error("the method list is not valid")]
    InvalidMethod,
    /// The permission of a rule is empty.
    #[error("the rule is not valid")]
    InvalidRule,
    /// A template that is malformed or names a parameter the path does not have.
    #[error("the resource template is not valid")]
    InvalidTemplate,
    /// A header name that is not one.
    #[error("the header name is not valid")]
    InvalidHeader,
    /// A kind, a namespace or a metadata path that is empty.
    #[error("the subject source is not valid")]
    InvalidSubjectSource,
}

#[derive(Debug, Clone)]
pub(crate) enum SubjectSource {
    Header(HeaderName),
    Metadata { namespace: String, path: Vec<String> },
}

/// How Envoy's `CheckRequest` maps to Strig, and the limits of the gRPC server.
///
/// Everything that is not set denies: no routes, no subject source, nothing allowed.
#[derive(Clone)]
#[non_exhaustive]
pub struct EnvoyConfig {
    pub(crate) routes: RouteTable,
    pub(crate) subject_sources: Vec<SubjectSource>,
    pub(crate) subject_kind: String,
    pub(crate) roles_header: Option<HeaderName>,
    pub(crate) reasons: bool,
    pub(crate) path_resolver: Option<Arc<dyn PathResolver>>,
    pub(crate) max_concurrent_streams: u32,
}

impl EnvoyConfig {
    /// Default of the most HTTP/2 streams one connection may have open.
    pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 256;
    /// Default subject type.
    pub const DEFAULT_SUBJECT_KIND: &'static str = "user";
    /// Longest subject id or role the adapter accepts, in bytes. Past it there is no subject.
    pub const MAX_IDENTITY_BYTES: usize = 512;
    /// Most roles taken from the roles header.
    pub const MAX_ROLES: usize = 64;

    /// Adds a rule: `methods` is `*` or a list such as `GET,HEAD`, `pattern` is like
    /// `/documents/{id}` (`*` for any one segment, `**` at the end for the rest). The first rule
    /// that matches decides; a request that matches none is denied. Paths are matched decoded, and
    /// one that holds dot segments, an encoded `/` or `\`, or invalid UTF-8 matches nothing.
    ///
    /// # Errors
    ///
    /// [`EnvoyConfigError`] when the pattern, the methods or the rule cannot work, so a typo fails at
    /// startup instead of denying in silence.
    pub fn with_route(mut self, methods: &str, pattern: &str, rule: RouteRule) -> Result<Self, EnvoyConfigError> {
        self.routes.push(methods, pattern, rule)?;
        Ok(self)
    }

    /// Reads the subject id from a request header (Envoy sends names in lower case). Envoy must set
    /// it itself and drop what the client sent, for example from `claim_to_headers` of the JWT
    /// filter: the adapter trusts the header. A value that holds a comma (Envoy joined repeated
    /// headers) is not an id. Sources are tried in the order added.
    ///
    /// # Errors
    ///
    /// [`EnvoyConfigError::InvalidHeader`].
    pub fn with_subject_header(mut self, name: &str) -> Result<Self, EnvoyConfigError> {
        let name = HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes())
            .map_err(|_| EnvoyConfigError::InvalidHeader)?;
        self.subject_sources.push(SubjectSource::Header(name));
        Ok(self)
    }

    /// Reads the subject id from the dynamic metadata a filter put in the `CheckRequest`, such as
    /// `envoy.filters.http.jwt_authn` with the path `["payload", "sub"]`. The value at the path must
    /// be a string.
    ///
    /// # Errors
    ///
    /// [`EnvoyConfigError::InvalidSubjectSource`] when the namespace or the path is empty.
    pub fn with_subject_metadata<I, S>(mut self, namespace: &str, path: I) -> Result<Self, EnvoyConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let path: Vec<String> = path.into_iter().map(Into::into).collect();
        if namespace.is_empty() || path.is_empty() || path.iter().any(String::is_empty) {
            return Err(EnvoyConfigError::InvalidSubjectSource);
        }
        self.subject_sources.push(SubjectSource::Metadata {
            namespace: namespace.to_string(),
            path,
        });
        Ok(self)
    }

    /// The subject type. Default `user`, which carries the `authenticated` principal as
    /// `Subject::user` does; any other kind is the matching `Subject::of_kind` with the same
    /// principal, since the identity came from the proxy.
    ///
    /// # Errors
    ///
    /// [`EnvoyConfigError::InvalidSubjectSource`] when it is empty.
    pub fn with_subject_kind(mut self, kind: impl Into<String>) -> Result<Self, EnvoyConfigError> {
        let kind = kind.into();
        if kind.is_empty() {
            return Err(EnvoyConfigError::InvalidSubjectSource);
        }
        self.subject_kind = kind;
        Ok(self)
    }

    /// Reads the roles of the subject from a header, comma-separated. The same trust rule as the
    /// subject header applies. Off by default.
    ///
    /// # Errors
    ///
    /// [`EnvoyConfigError::InvalidHeader`].
    pub fn with_roles_header(mut self, name: &str) -> Result<Self, EnvoyConfigError> {
        let name = HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes())
            .map_err(|_| EnvoyConfigError::InvalidHeader)?;
        self.roles_header = Some(name);
        Ok(self)
    }

    /// Adds [`REASON_HEADER`] to a denial, with a fixed code (`no_route`, `no_subject`, `denied`,
    /// `unknown_resource`, `unavailable`, `bad_request`), never a grant, a role or a permission. Off
    /// by default.
    #[must_use]
    pub fn with_reasons(mut self, on: bool) -> Self {
        self.reasons = on;
        self
    }

    /// The server's own knowledge of where a resource sits, as for AuthZEN. Without one a resource
    /// has only its own step; a resolver that does not know it makes the answer a deny.
    #[must_use]
    pub fn with_path_resolver(mut self, resolver: Arc<dyn PathResolver>) -> Self {
        self.path_resolver = Some(resolver);
        self
    }

    /// The most HTTP/2 streams one connection may have open when [`EnvoyService::serve`] runs the
    /// server. At least one.
    #[must_use]
    pub fn with_max_concurrent_streams(mut self, streams: u32) -> Self {
        self.max_concurrent_streams = streams.max(1);
        self
    }
}

impl Default for EnvoyConfig {
    fn default() -> Self {
        Self {
            routes: RouteTable::default(),
            subject_sources: Vec::new(),
            subject_kind: Self::DEFAULT_SUBJECT_KIND.to_string(),
            roles_header: None,
            reasons: false,
            path_resolver: None,
            max_concurrent_streams: Self::DEFAULT_MAX_CONCURRENT_STREAMS,
        }
    }
}

impl fmt::Debug for EnvoyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvoyConfig")
            .field("routes", &self.routes)
            .field("subject_sources", &self.subject_sources)
            .field("subject_kind", &self.subject_kind)
            .field("roles_header", &self.roles_header)
            .field("reasons", &self.reasons)
            .field("path_resolver", &self.path_resolver.is_some())
            .field("max_concurrent_streams", &self.max_concurrent_streams)
            .finish()
    }
}
