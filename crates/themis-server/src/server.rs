//! The router: routes, deadlines and the fail-closed mapping of every error.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequest, Request as HttpRequest, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, response::IntoResponse};
use serde::Serialize;
use serde::de::DeserializeOwned;
use themis::{Attributes, Context, PathLayout, QueryContext, QueryLimits, Request, Value};

use crate::clock::{Clock, SystemClock};
use crate::config::ServerConfig;
use crate::error::{ApiError, ErrorCode};
use crate::source::{DecisionSource, Snapshot};
use crate::wire::{
    AccessRequest, AccessResponse, BatchRequest, BatchResponse, CheckRequest, CheckResponse, ListRequest, ListResponse,
    PartyDto, WhoEntry, WhoExcept, WhoRequest, WhoResponse, filter_parts, subject_dto, via_dto,
};

/// The decision service: build it from a source, take the [`Router`], serve it.
///
/// It does no authentication and no rate limiting: put the router behind the layers of the
/// application that embeds it. See `API.md` for the contract.
pub struct DecisionServer {
    source: Arc<dyn DecisionSource>,
    clock: Arc<dyn Clock>,
    config: ServerConfig,
}

impl DecisionServer {
    /// A server over `source`, with the system clock and the default [`ServerConfig`].
    pub fn new(source: Arc<dyn DecisionSource>) -> Self {
        Self {
            source,
            clock: Arc::new(SystemClock),
            config: ServerConfig::default(),
        }
    }

    /// Replaces the clock that gives the instant of every decision.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    #[must_use]
    pub fn with_config(mut self, config: ServerConfig) -> Self {
        self.config = config;
        self
    }

    /// The routes, ready for `axum::serve` or to be nested in a bigger router.
    pub fn router(self) -> Router {
        let body_limit = self.config.max_body_bytes;
        let state = AppState {
            source: self.source,
            clock: self.clock,
            config: self.config,
        };
        Router::new()
            .route("/v1/check", post(check))
            .route("/v1/check/batch", post(check_batch))
            .route("/v1/list", post(list))
            .route("/v1/who", post(who))
            .route("/v1/access", post(access))
            .route("/health/live", get(live))
            .route("/health/ready", get(ready))
            .fallback(not_found)
            .method_not_allowed_fallback(method_not_allowed)
            .layer(DefaultBodyLimit::max(body_limit))
            .with_state(state)
    }
}

#[derive(Clone)]
struct AppState {
    source: Arc<dyn DecisionSource>,
    clock: Arc<dyn Clock>,
    config: ServerConfig,
}

/// What a request's work needs besides the snapshot.
struct Run {
    now: u64,
    limits: QueryLimits,
}

impl AppState {
    /// Loads the snapshot and runs `work` on a blocking thread, all inside the request deadline.
    /// Whatever goes wrong becomes an [`ApiError`]; nothing here can end in an allow.
    async fn answer<T>(
        &self,
        headers: &HeaderMap,
        work: impl FnOnce(&Snapshot, &Run) -> Result<T, ApiError> + Send + 'static,
    ) -> Result<Json<T>, ApiError>
    where
        T: Serialize + Send + 'static,
    {
        let timeout = self.config.timeout_for(headers)?;
        let now = self.clock.now_ms().ok_or(ApiError::new(ErrorCode::ClockUnavailable))?;
        let run = Run {
            now,
            limits: self.config.query_limits,
        };
        let source = Arc::clone(&self.source);
        let job = async move {
            let snapshot = source.snapshot().await.map_err(|error| {
                tracing::error!(error = ?error, "the grant source failed");
                ApiError::new(ErrorCode::SourceUnavailable)
            })?;
            // The engine is plain CPU work: off the async workers, so the deadline can fire. The
            // blocking task cannot be cancelled; the query limits are what bound it.
            tokio::task::spawn_blocking(move || work(&snapshot, &run))
                .await
                .map_err(|error| {
                    tracing::error!(error = %error, "the decision task did not finish");
                    ApiError::new(ErrorCode::Internal)
                })?
        };
        match tokio::time::timeout(timeout, job).await {
            Ok(result) => result.map(Json),
            Err(_) => Err(ApiError::new(ErrorCode::DeadlineExceeded)),
        }
    }
}

/// `Json` with the stable error body for every way the body can be refused.
struct ApiJson<T>(T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: HttpRequest, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => {
                tracing::debug!(error = %rejection, "request body refused");
                Err(ApiError::new(rejection_code(&rejection)))
            }
        }
    }
}

fn rejection_code(rejection: &JsonRejection) -> ErrorCode {
    match rejection {
        JsonRejection::JsonSyntaxError(_) => ErrorCode::MalformedJson,
        JsonRejection::MissingJsonContentType(_) => ErrorCode::UnsupportedMediaType,
        JsonRejection::BytesRejection(_) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            ErrorCode::BodyTooLarge
        }
        _ => ErrorCode::InvalidRequest,
    }
}

// ---------------------------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------------------------

async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<CheckRequest>,
) -> Result<Json<CheckResponse>, ApiError> {
    state
        .answer(&headers, move |snapshot, run| decide(snapshot, run.now, &request))
        .await
}

async fn check_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<BatchRequest>,
) -> Result<Json<BatchResponse>, ApiError> {
    if request.checks.len() > state.config.max_batch {
        return Err(ApiError::new(ErrorCode::BatchTooLarge));
    }
    state
        .answer(&headers, move |snapshot, run| {
            // All or nothing: one failing item fails the batch, never a partial answer.
            let results = request
                .checks
                .iter()
                .map(|check| decide(snapshot, run.now, check))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(BatchResponse { results })
        })
        .await
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<ListRequest>,
) -> Result<Json<ListResponse>, ApiError> {
    if request
        .resources
        .as_ref()
        .is_some_and(|r| r.len() > state.config.max_resources)
    {
        return Err(ApiError::new(ErrorCode::TooManyResources));
    }
    state
        .answer(&headers, move |snapshot, run| list_filter(snapshot, run, &request))
        .await
}

async fn who(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<WhoRequest>,
) -> Result<Json<WhoResponse>, ApiError> {
    state
        .answer(&headers, move |snapshot, run| who_holds(snapshot, run, &request))
        .await
}

async fn access(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<AccessRequest>,
) -> Result<Json<AccessResponse>, ApiError> {
    state
        .answer(&headers, move |snapshot, run| access_on(snapshot, run, &request))
        .await
}

#[derive(Serialize)]
struct Status {
    status: &'static str,
}

async fn live() -> Json<Status> {
    Json(Status { status: "live" })
}

/// Ready means the source answers now, so an instance that cannot load grants leaves the pool
/// instead of denying everything.
async fn ready(State(state): State<AppState>) -> Result<Json<Status>, ApiError> {
    let wait = state.config.default_timeout.min(state.config.max_timeout);
    match tokio::time::timeout(wait, state.source.snapshot()).await {
        Ok(Ok(_)) => Ok(Json(Status { status: "ready" })),
        Ok(Err(error)) => {
            tracing::error!(error = ?error, "readiness: the grant source failed");
            Err(ApiError::new(ErrorCode::SourceUnavailable))
        }
        Err(_) => Err(ApiError::new(ErrorCode::DeadlineExceeded)),
    }
}

async fn not_found() -> impl IntoResponse {
    ApiError::new(ErrorCode::NotFound)
}

async fn method_not_allowed() -> impl IntoResponse {
    ApiError::new(ErrorCode::MethodNotAllowed)
}

// ---------------------------------------------------------------------------------------------
// Work, on the blocking thread
// ---------------------------------------------------------------------------------------------

/// The request's environment with `now` taken from the server clock, so the validity windows and
/// the ABAC `env.now` read the same instant.
fn env_at(env: &Attributes, now: u64) -> Result<Attributes, ApiError> {
    let now = i64::try_from(now).map_err(|_| ApiError::new(ErrorCode::ClockUnavailable))?;
    let mut env = env.clone();
    env.insert("now".to_string(), Value::Int(now));
    Ok(env)
}

fn query_context<'a>(snapshot: &'a Snapshot, env: &'a Attributes, run: &Run) -> QueryContext<'a> {
    let mut ctx = QueryContext::new(&snapshot.grants)
        .with_limits(run.limits)
        .with_env(env)
        .at(run.now);
    if let Some(tuples) = &snapshot.tuples {
        ctx = ctx.with_tuples(tuples);
    }
    ctx
}

fn decide(snapshot: &Snapshot, now: u64, request: &CheckRequest) -> Result<CheckResponse, ApiError> {
    let env = env_at(&request.env, now)?;
    let mut ctx = Context::new(&snapshot.grants).with_env(&env).at(now);
    if let Some(tuples) = &snapshot.tuples {
        ctx = ctx.with_tuples(tuples);
    }
    let asked = Request::new(&request.subject, &request.permission, &request.resource);
    Ok(CheckResponse {
        decision: snapshot.engine.decide(&ctx, &asked),
        evaluated_at: now,
        requested_at: request.at,
    })
}

fn list_filter(snapshot: &Snapshot, run: &Run, request: &ListRequest) -> Result<ListResponse, ApiError> {
    let layout = match &request.layout {
        None => PathLayout::new(request.kind.as_str()),
        Some(kinds) => {
            let mut kinds = kinds.iter();
            let first = kinds.next().ok_or(ApiError::new(ErrorCode::InvalidRequest))?;
            kinds.fold(PathLayout::new(first.as_str()), |layout, kind| {
                layout.within(kind.as_str())
            })
        }
    };
    let env = env_at(&request.env, run.now)?;
    let ctx = query_context(snapshot, &env, run);
    let filter = snapshot
        .engine
        .list(&ctx, &request.subject, &request.permission, &request.kind);
    let (exact, shape, residual, warnings) = filter_parts(&filter, &layout)?;
    let ids = request.resources.as_ref().map(|resources| {
        let mut ids = filter.resolve_with(&snapshot.engine, &ctx.context(), resources);
        ids.sort();
        ids.dedup();
        ids
    });
    Ok(ListResponse {
        evaluated_at: run.now,
        requested_at: request.at,
        kind: request.kind.clone(),
        permission: request.permission.clone(),
        exact,
        shape,
        residual,
        warnings,
        ids,
    })
}

fn who_holds(snapshot: &Snapshot, run: &Run, request: &WhoRequest) -> Result<WhoResponse, ApiError> {
    let env = env_at(&request.env, run.now)?;
    let ctx = query_context(snapshot, &env, run);
    let (entries, except) = match &request.resource {
        Some(resource) => {
            let found = snapshot.engine.who_can_on(&ctx, &request.permission, resource)?;
            let entries = found
                .entries
                .iter()
                .map(|entry| {
                    Ok(WhoEntry {
                        subject: subject_dto(&entry.subject)?,
                        via: Some(via_dto(&entry.via)?),
                    })
                })
                .collect::<Result<Vec<_>, ApiError>>()?;
            let except = found
                .except
                .iter()
                .map(|pair| {
                    Ok(WhoExcept {
                        allowed: subject_dto(&pair.allowed)?,
                        with: subject_dto(&pair.with)?,
                    })
                })
                .collect::<Result<Vec<_>, ApiError>>()?;
            (entries, except)
        }
        None => {
            let entries = snapshot
                .engine
                .who_can(&ctx, &request.permission)
                .iter()
                .map(|subject| {
                    Ok(WhoEntry {
                        subject: subject_dto(subject)?,
                        via: None,
                    })
                })
                .collect::<Result<Vec<_>, ApiError>>()?;
            (entries, Vec::new())
        }
    };
    Ok(WhoResponse {
        evaluated_at: run.now,
        requested_at: request.at,
        permission: request.permission.clone(),
        entries,
        except,
    })
}

fn access_on(snapshot: &Snapshot, run: &Run, request: &AccessRequest) -> Result<AccessResponse, ApiError> {
    let env = env_at(&request.env, run.now)?;
    let ctx = query_context(snapshot, &env, run);
    let parties = snapshot
        .engine
        .access_of(&ctx, &request.resource)?
        .iter()
        .map(|party| {
            Ok(PartyDto {
                subject: subject_dto(&party.subject)?,
                permissions: party.permissions.iter().cloned().collect(),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(AccessResponse {
        evaluated_at: run.now,
        requested_at: request.at,
        parties,
    })
}
