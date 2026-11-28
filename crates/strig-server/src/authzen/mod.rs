//! The OpenID AuthZEN Authorization API 1.0 (Final, 11 January 2026), served next to `/v1`.
//!
//! Spec: <https://openid.net/specs/authorization-api-1_0.html>. The server is the PDP. It serves
//! `POST /access/v1/evaluation`, `/access/v1/evaluations`, `/access/v1/search/subject`,
//! `/access/v1/search/action` and, when a [`ResourceCatalog`] is configured,
//! `/access/v1/search/resource`, plus `GET /.well-known/authzen-configuration` when an issuer is
//! configured. Deadlines, body limits, the work budget and whatever layers the embedder puts
//! around the router apply as they do to `/v1`. `API.md` has the mapping.

mod handlers;
mod map;
mod wire;

use std::fmt;
use std::sync::Arc;

use axum::Router;
use axum::extract::Request as HttpRequest;
use axum::http::{HeaderName, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use strig::{Anchor, Resource};

use crate::server::AppState;
use crate::source::SourceError;

pub(crate) const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Request header that asks for the `reason` of a decision in the response `context`. It counts
/// only when [`AuthzenConfig::with_reasons`] is on.
pub const REASON_HEADER: &str = "x-strig-reason";

/// The broader steps of a resource's path, known to the server.
///
/// With one configured, the path of every resource comes from here and the `path` property of the
/// request is ignored: the caller cannot place a resource inside an organization the server does
/// not know it in. It runs on the blocking pool, so it may block.
pub trait PathResolver: Send + Sync + 'static {
    /// The steps broader than `kind:id`, from the most specific to the broadest, or `None` when
    /// the resource is not known (the decision is then a deny).
    fn broader_steps(&self, kind: &str, id: &str) -> Option<Vec<Anchor>>;
}

/// The resources of a kind, for the Resource Search API.
///
/// Strig decides one resource at a time and cannot enumerate what it was never told about, so
/// the embedder says which resources exist. Each one carries its full path and attributes, and
/// is decided like a `/v1/check` resource. It runs on the blocking pool, so it may block.
pub trait ResourceCatalog: Send + Sync + 'static {
    /// Every resource of `kind`.
    ///
    /// # Errors
    ///
    /// [`SourceError::Unavailable`]; the search then fails and returns nothing.
    fn resources(&self, kind: &str) -> Result<Vec<Resource>, SourceError>;
}

/// Why an [`AuthzenConfig`] value was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthzenConfigError {
    /// The issuer must be an `https` URL with a host and no query or fragment.
    #[error("the issuer must be an https URL with a host, without query or fragment")]
    InvalidIssuer,
    /// A property name that is empty or used for two conventions.
    #[error("the property names of the conventions must be non-empty and distinct")]
    InvalidProperty,
}

/// The conventions that map AuthZEN to Strig, and the limits of the search endpoints.
#[derive(Clone)]
#[non_exhaustive]
pub struct AuthzenConfig {
    issuer: Option<String>,
    roles_property: String,
    principals_property: String,
    path_property: String,
    authenticated_kinds: Vec<String>,
    reasons: bool,
    path_resolver: Option<Arc<dyn PathResolver>>,
    resource_catalog: Option<Arc<dyn ResourceCatalog>>,
    max_page_size: usize,
}

impl AuthzenConfig {
    /// Default of the `roles` property of a subject.
    pub const DEFAULT_ROLES_PROPERTY: &'static str = "roles";
    /// Default of the `principals` property of a subject.
    pub const DEFAULT_PRINCIPALS_PROPERTY: &'static str = "principals";
    /// Default of the `path` property of a resource.
    pub const DEFAULT_PATH_PROPERTY: &'static str = "path";
    /// Default of the largest page of a search.
    pub const DEFAULT_MAX_PAGE_SIZE: usize = 1_000;

    /// The identifier the metadata document carries as `policy_decision_point` and the base of
    /// its endpoint URLs. Without it the metadata route does not exist.
    ///
    /// # Errors
    ///
    /// [`AuthzenConfigError::InvalidIssuer`] unless it is an `https` URL with a host and no query
    /// or fragment. A trailing `/` is dropped.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Result<Self, AuthzenConfigError> {
        let issuer = issuer.into();
        let rest = issuer
            .strip_prefix("https://")
            .ok_or(AuthzenConfigError::InvalidIssuer)?;
        if rest.is_empty() || rest.starts_with('/') || issuer.contains(['?', '#']) {
            return Err(AuthzenConfigError::InvalidIssuer);
        }
        self.issuer = Some(issuer.trim_end_matches('/').to_string());
        Ok(self)
    }

    /// The names of the properties that carry what Strig keeps outside the attributes: the roles
    /// and principals of a subject, and the broader path steps of a resource. They are read from
    /// `properties` and do not become attributes.
    ///
    /// # Errors
    ///
    /// [`AuthzenConfigError::InvalidProperty`] when a name is empty or two are the same.
    pub fn with_properties(
        mut self,
        roles: impl Into<String>,
        principals: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, AuthzenConfigError> {
        let (roles, principals, path) = (roles.into(), principals.into(), path.into());
        let empty = roles.is_empty() || principals.is_empty() || path.is_empty();
        if empty || roles == principals || roles == path || principals == path {
            return Err(AuthzenConfigError::InvalidProperty);
        }
        self.roles_property = roles;
        self.principals_property = principals;
        self.path_property = path;
        Ok(self)
    }

    /// The subject types that carry the `authenticated` principal on their own, as `Subject::user`
    /// does. Default: `user`. An AuthZEN subject always has an id, so the PEP has no way to say it.
    #[must_use]
    pub fn with_authenticated_kinds<I, S>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.authenticated_kinds = kinds.into_iter().map(Into::into).collect();
        self
    }

    /// Lets a request ask for the `reason` of a decision with [`REASON_HEADER`]. Off by default.
    /// The reason is a fixed code, never a grant id, a role or a permission.
    #[must_use]
    pub fn with_reasons(mut self, on: bool) -> Self {
        self.reasons = on;
        self
    }

    /// The server's own knowledge of where a resource sits.
    #[must_use]
    pub fn with_path_resolver(mut self, resolver: Arc<dyn PathResolver>) -> Self {
        self.path_resolver = Some(resolver);
        self
    }

    /// Turns the Resource Search API on, over the resources `catalog` lists.
    #[must_use]
    pub fn with_resource_catalog(mut self, catalog: Arc<dyn ResourceCatalog>) -> Self {
        self.resource_catalog = Some(catalog);
        self
    }

    /// The most results in one page of a search, and the size of a page that asks for none. At
    /// least one.
    #[must_use]
    pub fn with_max_page_size(mut self, size: usize) -> Self {
        self.max_page_size = size.max(1);
        self
    }

    pub(crate) fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    pub(crate) fn has_resource_search(&self) -> bool {
        self.resource_catalog.is_some()
    }
}

impl Default for AuthzenConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            roles_property: Self::DEFAULT_ROLES_PROPERTY.to_string(),
            principals_property: Self::DEFAULT_PRINCIPALS_PROPERTY.to_string(),
            path_property: Self::DEFAULT_PATH_PROPERTY.to_string(),
            authenticated_kinds: vec!["user".to_string()],
            reasons: false,
            path_resolver: None,
            resource_catalog: None,
            max_page_size: Self::DEFAULT_MAX_PAGE_SIZE,
        }
    }
}

impl fmt::Debug for AuthzenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthzenConfig")
            .field("issuer", &self.issuer)
            .field("roles_property", &self.roles_property)
            .field("principals_property", &self.principals_property)
            .field("path_property", &self.path_property)
            .field("authenticated_kinds", &self.authenticated_kinds)
            .field("reasons", &self.reasons)
            .field("path_resolver", &self.path_resolver.is_some())
            .field("resource_catalog", &self.resource_catalog.is_some())
            .field("max_page_size", &self.max_page_size)
            .finish()
    }
}

pub(crate) fn routes(config: &AuthzenConfig) -> Router<AppState> {
    let mut routes = Router::new()
        .route("/access/v1/evaluation", post(handlers::evaluation))
        .route("/access/v1/evaluations", post(handlers::evaluations))
        .route("/access/v1/search/subject", post(handlers::search_subject))
        .route("/access/v1/search/action", post(handlers::search_action));
    if config.has_resource_search() {
        routes = routes.route("/access/v1/search/resource", post(handlers::search_resource));
    }
    if config.issuer().is_some() {
        routes = routes.route("/.well-known/authzen-configuration", get(handlers::metadata));
    }
    routes.layer(middleware::from_fn(envelope))
}

/// What the spec asks of every answer of the API: the request id is echoed, and a failure of the
/// server is a `500`, the only server error the binding has. Whatever is not a `200` is still no
/// access; the body keeps the stable code.
async fn envelope(request: HttpRequest, next: Next) -> Response {
    let request_id = request.headers().get(REQUEST_ID).cloned();
    let mut response = next.run(request).await;
    if response.status() == StatusCode::SERVICE_UNAVAILABLE {
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    }
    if let Some(id) = request_id {
        response.headers_mut().insert(REQUEST_ID, id);
    }
    response
}
