//! The routes of the AuthZEN API and the work behind them.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use serde::Serialize;
use serde_json::{Value as Json_, json};
use strig::{AUTHENTICATED, Reason, Subject, SubjectRef};

use super::map::{self, Malformed, ResourceError};
use super::wire::{
    Action, ActionOut, DecisionOut, Entity, EntityOut, EvaluationItem, EvaluationRequest, EvaluationsOut,
    EvaluationsRequest, MetadataOut, PageOut, Properties, SearchOut, SearchRequest,
};
use super::{AuthzenConfig, REASON_HEADER};
use crate::error::{ApiError, ErrorCode};
use crate::server::{ApiJson, AppState, Deadline, Run, decide_parts, query_context};
use crate::source::{Snapshot, SourceError};

fn config_of(state: &AppState) -> Result<Arc<AuthzenConfig>, ApiError> {
    state.authzen.clone().ok_or_else(|| ApiError::new(ErrorCode::NotFound))
}

fn invalid(error: &Malformed) -> ApiError {
    tracing::debug!(reason = error.0, "AuthZEN request refused");
    ApiError::new(ErrorCode::InvalidRequest)
}

fn wants_reason(config: &AuthzenConfig, headers: &HeaderMap) -> bool {
    config.reasons
        && headers
            .get(REASON_HEADER)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

// ---------------------------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------------------------

/// A fixed code for the `reason` of a decision: nothing of the grant, the role or the permission.
fn reason_code(reason: &Reason) -> &'static str {
    match reason {
        Reason::Override { .. } => "override",
        Reason::Grant { .. } => "grant",
        Reason::NoApplicableGrant => "no_applicable_grant",
        Reason::UnknownPermission => "unknown_permission",
        Reason::MissingPrerequisite { .. } => "missing_prerequisite",
    }
}

impl DecisionOut {
    fn of(decision: &strig::Decision, explain: bool) -> Self {
        let context = explain.then(|| {
            let mut context = Properties::new();
            context.insert("reason".to_string(), json!(reason_code(&decision.reason)));
            context
        });
        Self {
            decision: decision.is_allowed(),
            context,
        }
    }

    /// A deny for a request that could not be decided, with the error where the spec puts it.
    fn error(status: u16, message: &str) -> Self {
        let mut context = Properties::new();
        context.insert("error".to_string(), json!({"status": status, "message": message}));
        Self {
            decision: false,
            context: Some(context),
        }
    }

    /// Marks the denial that ended an `deny_on_first_deny` run, as the spec's example does.
    fn mark_short_circuit(&mut self) {
        let context = self.context.get_or_insert_with(Properties::new);
        if !context.contains_key("reason") {
            context.insert("code".to_string(), json!("200"));
            context.insert("reason".to_string(), json!("deny_on_first_deny"));
        }
    }
}

enum Failure {
    Malformed(Malformed),
    Api(ApiError),
}

impl From<Malformed> for Failure {
    fn from(error: Malformed) -> Self {
        Self::Malformed(error)
    }
}

impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

struct Resolved<'a> {
    subject: &'a Entity,
    action: &'a Action,
    resource: &'a Entity,
    context: Option<&'a Properties>,
}

fn evaluate(
    config: &AuthzenConfig,
    snapshot: &Snapshot,
    run: &Run,
    item: &Resolved<'_>,
    explain: bool,
) -> Result<DecisionOut, Failure> {
    let subject = config.subject(item.subject)?;
    let env = map::env(item.context)?;
    if item.action.name.is_empty() {
        return Err(Malformed("the action name is empty").into());
    }
    let resource = match config.resource(item.resource) {
        Ok(resource) => resource,
        Err(ResourceError::Malformed(error)) => return Err(error.into()),
        Err(ResourceError::Unknown) => return Ok(DecisionOut::error(404, "resource not found")),
    };
    let decision = decide_parts(snapshot, run.now, &subject, &item.action.name, &resource, &env)?;
    Ok(DecisionOut::of(&decision, explain))
}

pub(crate) async fn evaluation(
    State(state): State<AppState>,
    deadline: Deadline,
    headers: HeaderMap,
    ApiJson(request): ApiJson<EvaluationRequest>,
) -> Result<Json<DecisionOut>, ApiError> {
    let config = config_of(&state)?;
    let explain = wants_reason(&config, &headers);
    state
        .answer(deadline, move |snapshot, run| {
            let item = Resolved {
                subject: &request.subject,
                action: &request.action,
                resource: &request.resource,
                context: request.context.as_ref(),
            };
            single(&config, snapshot, run, &item, explain)
        })
        .await
}

fn single(
    config: &AuthzenConfig,
    snapshot: &Snapshot,
    run: &Run,
    item: &Resolved<'_>,
    explain: bool,
) -> Result<DecisionOut, ApiError> {
    match evaluate(config, snapshot, run, item, explain) {
        Ok(out) => Ok(out),
        Err(Failure::Malformed(error)) => Err(invalid(&error)),
        Err(Failure::Api(error)) => Err(error),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Semantic {
    ExecuteAll,
    DenyOnFirstDeny,
    PermitOnFirstPermit,
}

impl Semantic {
    fn parse(name: Option<&str>) -> Result<Self, ApiError> {
        match name {
            None | Some("execute_all") => Ok(Self::ExecuteAll),
            Some("deny_on_first_deny") => Ok(Self::DenyOnFirstDeny),
            Some("permit_on_first_permit") => Ok(Self::PermitOnFirstPermit),
            Some(_) => Err(ApiError::new(ErrorCode::InvalidRequest)),
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum EvaluationsAnswer {
    One(DecisionOut),
    Many(EvaluationsOut),
}

/// The item over the top-level defaults; a key missing from both makes the payload malformed.
fn merged<'a>(item: &'a EvaluationItem, defaults: &'a EvaluationItem) -> Result<Resolved<'a>, ApiError> {
    let missing = || ApiError::new(ErrorCode::InvalidRequest);
    Ok(Resolved {
        subject: item
            .subject
            .as_ref()
            .or(defaults.subject.as_ref())
            .ok_or_else(missing)?,
        action: item.action.as_ref().or(defaults.action.as_ref()).ok_or_else(missing)?,
        resource: item
            .resource
            .as_ref()
            .or(defaults.resource.as_ref())
            .ok_or_else(missing)?,
        context: item.context.as_ref().or(defaults.context.as_ref()),
    })
}

pub(crate) async fn evaluations(
    State(state): State<AppState>,
    deadline: Deadline,
    headers: HeaderMap,
    ApiJson(request): ApiJson<EvaluationsRequest>,
) -> Result<Json<EvaluationsAnswer>, ApiError> {
    let config = config_of(&state)?;
    let explain = wants_reason(&config, &headers);
    let semantic = Semantic::parse(
        request
            .options
            .as_ref()
            .and_then(|options| options.evaluations_semantic.as_deref()),
    )?;
    let count = request.evaluations.as_ref().map_or(0, Vec::len);
    if count > state.config.max_batch {
        return Err(ApiError::new(ErrorCode::BatchTooLarge));
    }
    // Checked before the source is asked: a payload that cannot be right is a 400.
    if let Some(items) = request.evaluations.as_ref().filter(|items| !items.is_empty()) {
        for item in items {
            merged(item, &request.defaults)?;
        }
    } else {
        merged(&request.defaults, &EvaluationItem::default())?;
    }
    state
        .answer(deadline, move |snapshot, run| {
            let Some(items) = request.evaluations.as_ref().filter(|items| !items.is_empty()) else {
                let none = EvaluationItem::default();
                let item = merged(&request.defaults, &none)?;
                return single(&config, snapshot, run, &item, explain).map(EvaluationsAnswer::One);
            };
            run.ensure_budget(items.len(), snapshot.grants.len())?;
            let mut decisions = Vec::with_capacity(items.len());
            for item in items {
                run.ensure_live()?;
                let item = merged(item, &request.defaults)?;
                let mut out = match evaluate(&config, snapshot, run, &item, explain) {
                    Ok(out) => out,
                    Err(Failure::Malformed(error)) => DecisionOut::error(400, error.0),
                    Err(Failure::Api(error)) => return Err(error),
                };
                let stop = match semantic {
                    Semantic::DenyOnFirstDeny if !out.decision => {
                        out.mark_short_circuit();
                        true
                    }
                    Semantic::PermitOnFirstPermit => out.decision,
                    _ => false,
                };
                decisions.push(out);
                if stop {
                    break;
                }
            }
            Ok(EvaluationsAnswer::Many(EvaluationsOut { evaluations: decisions }))
        })
        .await
}

// ---------------------------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------------------------

/// Where a page starts and how long it is, read before the source is asked.
struct Paging {
    offset: usize,
    limit: usize,
    fingerprint: u64,
}

/// FNV-1a: a hash that every instance computes the same, so a token from one is read by another.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

impl Paging {
    /// The token ties a page to its request: the same entities and limit, or the token is refused.
    fn of(config: &AuthzenConfig, request: &SearchRequest) -> Result<Self, ApiError> {
        let page = request.page.as_ref();
        let asked = page.and_then(|page| page.limit);
        let limit = match asked {
            Some(n) if n > 0 => usize::try_from(n).unwrap_or(usize::MAX).min(config.max_page_size),
            _ => config.max_page_size,
        };
        let basis = serde_json::to_vec(&(
            &request.subject,
            &request.action,
            &request.resource,
            &request.context,
            asked,
        ))
        .map_err(|_| ApiError::new(ErrorCode::InvalidRequest))?;
        let fingerprint = fnv1a(&basis);
        let offset = match page
            .and_then(|page| page.token.as_deref())
            .filter(|token| !token.is_empty())
        {
            None => 0,
            Some(token) => token
                .split_once('.')
                .filter(|(_, tag)| u64::from_str_radix(tag, 16) == Ok(fingerprint))
                .and_then(|(offset, _)| offset.parse().ok())
                .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest))?,
        };
        Ok(Self {
            offset,
            limit,
            fingerprint,
        })
    }

    fn page<T>(&self, mut all: Vec<T>, context: Option<Properties>) -> SearchOut<T> {
        let total = all.len();
        let start = self.offset.min(total);
        let end = start.saturating_add(self.limit).min(total);
        let results: Vec<T> = all.drain(start..end).collect();
        let next_token = if end < total {
            format!("{end}.{:016x}", self.fingerprint)
        } else {
            String::new()
        };
        SearchOut {
            page: PageOut {
                next_token,
                count: results.len(),
                total,
            },
            context,
            results,
        }
    }
}

fn entity<'a>(slot: Option<&'a Entity>, what: &'static str) -> Result<&'a Entity, ApiError> {
    slot.ok_or_else(|| invalid(&Malformed(what)))
}

fn bare_subject(config: &AuthzenConfig, kind: &str, id: &str) -> Subject {
    let subject = Subject::of_kind(kind, id);
    if config
        .authenticated_kinds
        .iter()
        .any(|authenticated| authenticated == kind)
    {
        subject.with_principal(AUTHENTICATED)
    } else {
        subject
    }
}

fn incomplete() -> Properties {
    let mut context = Properties::new();
    context.insert("incomplete".to_string(), Json_::Bool(true));
    context
}

pub(crate) async fn search_subject(
    State(state): State<AppState>,
    deadline: Deadline,
    ApiJson(request): ApiJson<SearchRequest>,
) -> Result<Json<SearchOut<EntityOut>>, ApiError> {
    let config = config_of(&state)?;
    let paging = Paging::of(&config, &request)?;
    entity(request.subject.as_ref(), "the subject is missing")?;
    entity(request.resource.as_ref(), "the resource is missing")?;
    request
        .action
        .as_ref()
        .ok_or_else(|| invalid(&Malformed("the action is missing")))?;
    state
        .answer(deadline, move |snapshot, run| {
            let (Some(subject), Some(resource), Some(action)) = (&request.subject, &request.resource, &request.action)
            else {
                return Err(ApiError::new(ErrorCode::InvalidRequest));
            };
            let kind = config
                .open_kind(subject, "the subject type is empty")
                .map_err(|e| invalid(&e))?;
            let env = map::env(request.context.as_ref()).map_err(|e| invalid(&e))?;
            let resource = match config.resource(resource) {
                Ok(resource) => resource,
                Err(ResourceError::Malformed(error)) => return Err(invalid(&error)),
                Err(ResourceError::Unknown) => return Ok(paging.page(Vec::new(), None)),
            };
            let ctx = query_context(snapshot, &env, run);
            run.ensure_live()?;
            let found = snapshot.engine.who_can_on(&ctx, &action.name, &resource)?;
            let mut named = BTreeSet::new();
            let mut left_out = false;
            for entry in &found.entries {
                match &entry.subject {
                    SubjectRef::User { id } if kind == "user" => {
                        named.insert(id.clone());
                    }
                    SubjectRef::Object { kind: of, id } if of == kind => {
                        named.insert(id.clone());
                    }
                    _ => left_out = true,
                }
            }
            run.ensure_budget(named.len(), snapshot.grants.len())?;
            // `who_can_on` decides parties as bare archetypes; each name is settled by a real
            // decision, so what comes out is what the Evaluation API would allow.
            let mut results = Vec::new();
            for id in named {
                run.ensure_live()?;
                let subject = bare_subject(&config, kind, &id);
                if decide_parts(snapshot, run.now, &subject, &action.name, &resource, &env)?.is_allowed() {
                    results.push(EntityOut {
                        id,
                        kind: kind.to_string(),
                    });
                }
            }
            Ok(paging.page(results, left_out.then(incomplete)))
        })
        .await
}

pub(crate) async fn search_action(
    State(state): State<AppState>,
    deadline: Deadline,
    ApiJson(request): ApiJson<SearchRequest>,
) -> Result<Json<SearchOut<ActionOut>>, ApiError> {
    let config = config_of(&state)?;
    let paging = Paging::of(&config, &request)?;
    entity(request.subject.as_ref(), "the subject is missing")?;
    entity(request.resource.as_ref(), "the resource is missing")?;
    state
        .answer(deadline, move |snapshot, run| {
            let (Some(subject), Some(resource)) = (&request.subject, &request.resource) else {
                return Err(ApiError::new(ErrorCode::InvalidRequest));
            };
            let subject = config.subject(subject).map_err(|e| invalid(&e))?;
            let env = map::env(request.context.as_ref()).map_err(|e| invalid(&e))?;
            let resource = match config.resource(resource) {
                Ok(resource) => resource,
                Err(ResourceError::Malformed(error)) => return Err(invalid(&error)),
                Err(ResourceError::Unknown) => return Ok(paging.page(Vec::new(), None)),
            };
            let permissions = snapshot.engine.catalog().all();
            run.ensure_budget(permissions.len(), snapshot.grants.len())?;
            let mut results = Vec::new();
            for def in permissions {
                run.ensure_live()?;
                if decide_parts(snapshot, run.now, &subject, &def.key, &resource, &env)?.is_allowed() {
                    results.push(ActionOut { name: def.key.clone() });
                }
            }
            results.sort();
            Ok(paging.page(results, None))
        })
        .await
}

pub(crate) async fn search_resource(
    State(state): State<AppState>,
    deadline: Deadline,
    ApiJson(request): ApiJson<SearchRequest>,
) -> Result<Json<SearchOut<EntityOut>>, ApiError> {
    let config = config_of(&state)?;
    let max_resources = state.config.max_resources;
    let paging = Paging::of(&config, &request)?;
    entity(request.subject.as_ref(), "the subject is missing")?;
    entity(request.resource.as_ref(), "the resource is missing")?;
    request
        .action
        .as_ref()
        .ok_or_else(|| invalid(&Malformed("the action is missing")))?;
    state
        .answer(deadline, move |snapshot, run| {
            let (Some(subject), Some(resource), Some(action), Some(catalog)) = (
                &request.subject,
                &request.resource,
                &request.action,
                &config.resource_catalog,
            ) else {
                return Err(ApiError::new(ErrorCode::InvalidRequest));
            };
            let subject = config.subject(subject).map_err(|e| invalid(&e))?;
            let env = map::env(request.context.as_ref()).map_err(|e| invalid(&e))?;
            let kind = config
                .open_kind(resource, "the resource type is empty")
                .map_err(|e| invalid(&e))?;
            let candidates = catalog.resources(kind).map_err(|error: SourceError| {
                tracing::error!(error = ?error, "the resource catalog failed");
                ApiError::new(ErrorCode::SourceUnavailable)
            })?;
            if candidates.len() > max_resources {
                return Err(ApiError::new(ErrorCode::QueryLimitExceeded));
            }
            run.ensure_budget(candidates.len(), snapshot.grants.len())?;
            let mut results = Vec::new();
            for candidate in &candidates {
                run.ensure_live()?;
                let Some(anchor) = candidate.primary().filter(|anchor| anchor.kind == kind) else {
                    continue;
                };
                let Some(id) = anchor.id.clone() else { continue };
                if decide_parts(snapshot, run.now, &subject, &action.name, candidate, &env)?.is_allowed() {
                    results.push(EntityOut {
                        id,
                        kind: kind.to_string(),
                    });
                }
            }
            results.sort();
            results.dedup();
            Ok(paging.page(results, None))
        })
        .await
}

// ---------------------------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------------------------

pub(crate) async fn metadata(State(state): State<AppState>) -> Result<Json<MetadataOut>, ApiError> {
    let config = config_of(&state)?;
    let issuer = config.issuer().ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let at = |path: &str| format!("{issuer}{path}");
    Ok(Json(MetadataOut {
        policy_decision_point: issuer.to_string(),
        access_evaluation_endpoint: at("/access/v1/evaluation"),
        access_evaluations_endpoint: at("/access/v1/evaluations"),
        search_subject_endpoint: at("/access/v1/search/subject"),
        search_action_endpoint: at("/access/v1/search/action"),
        search_resource_endpoint: config.has_resource_search().then(|| at("/access/v1/search/resource")),
    }))
}
