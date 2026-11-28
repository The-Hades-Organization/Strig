//! The decision behind one `Check`: nothing here can end in an allow unless the engine said so.

use std::sync::Arc;

use strig::{AUTHENTICATED, Attributes, Resource, Subject};

use super::proto::{AttributeContext, CheckRequest, CheckResponse, HttpRequest};
use super::route::RouteRule;
use super::{EnvoyConfig, SubjectSource};
use crate::server::{AppState, Deadline, decide_parts};

/// The outcome of a check, before it becomes a response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allow,
    /// A denial with its fixed code.
    Deny(&'static str),
}

impl Verdict {
    #[cfg(feature = "tracing")]
    pub(crate) fn outcome(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny(_) => "deny",
        }
    }

    pub(crate) fn into_response(self, reasons: bool) -> CheckResponse {
        match self {
            Self::Allow => CheckResponse::allow(),
            Self::Deny(code) => CheckResponse::deny(reasons.then_some(code)),
        }
    }
}

pub(crate) async fn verdict(state: &AppState, config: &Arc<EnvoyConfig>, request: &CheckRequest) -> Verdict {
    let Some(attributes) = &request.attributes else {
        return Verdict::Deny("bad_request");
    };
    let Some(http) = attributes.request.as_ref().and_then(|r| r.http.as_ref()) else {
        return Verdict::Deny("bad_request");
    };
    let Some(matched) = config.routes.find(&http.method, &http.path) else {
        return Verdict::Deny("no_route");
    };
    let (permission, template) = match matched.rule {
        RouteRule::Public => return Verdict::Allow,
        RouteRule::Require { permission, resource } => (permission.clone(), resource),
    };
    let Some(subject) = subject_of(config, attributes, http) else {
        return Verdict::Deny("no_subject");
    };
    let Some((kind, id)) = template.render(&matched.params) else {
        return Verdict::Deny("bad_request");
    };
    let wait = state.config.default_timeout.min(state.config.max_timeout);
    let resolver = config.path_resolver.clone();
    let work = move |snapshot: &crate::source::Snapshot, run: &crate::server::Run| {
        let mut resource = Resource::new(kind.as_str(), id.as_str());
        if let Some(resolver) = &resolver {
            match resolver.broader_steps(&kind, &id) {
                Some(steps) => resource.path.extend(steps),
                None => return Ok(Verdict::Deny("unknown_resource")),
            }
        }
        let decision = decide_parts(snapshot, run.now, &subject, &permission, &resource, &Attributes::new())?;
        Ok(if decision.is_allowed() {
            Verdict::Allow
        } else {
            Verdict::Deny("denied")
        })
    };
    match state.answer_raw(Deadline::after(wait), work).await {
        Ok(verdict) => verdict,
        Err(_) => Verdict::Deny("unavailable"),
    }
}

fn header<'a>(http: &'a HttpRequest, name: &str) -> Option<&'a str> {
    http.headers.get(name).map(String::as_str)
}

/// A subject id: non-empty, bounded, one value only.
fn identity(value: &str) -> Option<&str> {
    let value = value.trim();
    let ok = !value.is_empty() && value.len() <= EnvoyConfig::MAX_IDENTITY_BYTES && !value.contains(',');
    ok.then_some(value)
}

fn from_metadata<'a>(context: &'a AttributeContext, namespace: &str, path: &[String]) -> Option<&'a str> {
    use prost_types::value::Kind;

    let mut fields = &context
        .metadata_context
        .as_ref()?
        .filter_metadata
        .get(namespace)?
        .fields;
    let (last, parents) = path.split_last()?;
    for step in parents {
        match fields.get(step)?.kind.as_ref()? {
            Kind::StructValue(inner) => fields = &inner.fields,
            _ => return None,
        }
    }
    match fields.get(last)?.kind.as_ref()? {
        Kind::StringValue(text) => Some(text),
        _ => None,
    }
}

fn subject_of(config: &EnvoyConfig, context: &AttributeContext, http: &HttpRequest) -> Option<Subject> {
    let id = config.subject_sources.iter().find_map(|source| {
        let raw = match source {
            SubjectSource::Header(name) => header(http, name.as_str()),
            SubjectSource::Metadata { namespace, path } => from_metadata(context, namespace, path),
        };
        raw.and_then(identity)
    })?;
    let mut subject = Subject::of_kind(config.subject_kind.as_str(), id).with_principal(AUTHENTICATED);
    if let Some(name) = &config.roles_header
        && let Some(list) = header(http, name.as_str())
    {
        let roles: Vec<&str> = list.split(',').map(str::trim).filter(|role| !role.is_empty()).collect();
        let too_many = roles.len() > EnvoyConfig::MAX_ROLES;
        if too_many || roles.iter().any(|role| role.len() > EnvoyConfig::MAX_IDENTITY_BYTES) {
            return None;
        }
        for role in roles {
            subject = subject.with_role(role);
        }
    }
    Some(subject)
}
