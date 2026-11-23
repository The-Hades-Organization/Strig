use crate::attr::Value;
use crate::decision::Request;
use crate::engine::{Context, Engine};
use crate::grant::Effect;
use crate::query::{AccessFilter, Expr, QueryContext, QueryError, SubjectRef};
use crate::resource::Resource;
use crate::subject::Subject;

/// What an [`Override`] is asked when a listing is planned: for this subject, permission and
/// resource kind, which resources would the override decide on?
#[non_exhaustive]
pub struct ReachRequest<'a> {
    pub engine: &'a Engine,
    pub ctx: &'a QueryContext<'a>,
    pub subject: &'a Subject,
    pub permission: &'a str,
    pub kind: &'a str,
}

impl ReachRequest<'_> {
    /// Listing of another permission by the grants only, without overrides (what
    /// [`Engine::decide_without_overrides`] answers resource by resource).
    pub fn holds(&self, permission: &str) -> AccessFilter {
        self.engine.plan(self.ctx, self.subject, permission, self.kind, false)
    }
}

/// What an [`Override`] is asked in a reverse query: which subjects does it let through on this
/// resource?
#[non_exhaustive]
pub struct SubjectsRequest<'a> {
    pub engine: &'a Engine,
    pub ctx: &'a QueryContext<'a>,
    pub permission: &'a str,
    pub resource: &'a Resource,
}

impl SubjectsRequest<'_> {
    /// Subjects with `permission` on the resource by the grants only, without overrides.
    ///
    /// # Errors
    ///
    /// The [`QueryError`] of the nested query (a limit, an unreadable deny).
    pub fn holders(&self, permission: &str) -> Result<Vec<SubjectRef>, QueryError> {
        Ok(self
            .engine
            .who_can_on_by_grants(self.ctx, permission, self.resource)?
            .subjects()
            .cloned()
            .collect())
    }
}

/// Where an override applies, as a condition on the resource.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum OverrideGate {
    /// A structural condition on the resource.
    Expr(Expr),
    /// Wherever the nested listing (by the grants only) includes the resource.
    Holds(Box<AccessFilter>),
}

/// How an override answers a listing.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum OverrideReach {
    /// The override cannot be inspected without the resource: the listing leaves the resources it
    /// might decide on as undecided residue, never as allowed.
    #[default]
    Opaque,
    /// The override never decides for this subject.
    Never,
    /// Allows wherever the gate holds.
    Allows(OverrideGate),
    /// Denies wherever the gate holds.
    Denies(OverrideGate),
}

/// Decides before the grants. Meant for the resource owner, superadmin, suspended account.
///
/// The engine consults the overrides in order and stops at the first one that returns `Some`.
/// Per-permission exceptions are configured in [`crate::EngineBuilder::override_except`].
pub trait Override: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, engine: &Engine, ctx: &Context<'_>, request: &Request<'_>) -> Option<Effect>;

    /// Describes where this override decides, for listings ([`Engine::list`]). The default is
    /// [`OverrideReach::Opaque`]: a custom override stays residue until it implements this.
    fn reach(&self, _request: &ReachRequest<'_>) -> OverrideReach {
        OverrideReach::Opaque
    }

    /// Subjects this override lets through on the resource, for reverse queries
    /// ([`Engine::who_can_on`]). The default names none.
    ///
    /// # Errors
    ///
    /// Pass on the [`QueryError`] of a nested query ([`SubjectsRequest::holders`]).
    fn subjects(&self, _request: &SubjectsRequest<'_>) -> Result<Vec<SubjectRef>, QueryError> {
        Ok(Vec::new())
    }
}

/// Allows everything for the subject whose id is in the resource's `attr` attribute.
#[derive(Debug, Clone)]
pub struct ResourceOwner {
    attr: String,
}

impl ResourceOwner {
    pub fn new(attr: impl Into<String>) -> Self {
        Self { attr: attr.into() }
    }
}

impl Override for ResourceOwner {
    fn name(&self) -> &str {
        "resource_owner"
    }

    fn evaluate(&self, _: &Engine, _: &Context<'_>, request: &Request<'_>) -> Option<Effect> {
        let id = request.subject.id.as_deref()?;
        match request.resource.attrs.get(&self.attr)? {
            Value::Str(owner) if owner == id => Some(Effect::Allow),
            _ => None,
        }
    }

    fn reach(&self, request: &ReachRequest<'_>) -> OverrideReach {
        match request.subject.id.as_deref() {
            None => OverrideReach::Never,
            Some(id) => OverrideReach::Allows(OverrideGate::Expr(Expr::AttrEq {
                attr: self.attr.clone(),
                value: id.to_string(),
            })),
        }
    }

    fn subjects(&self, request: &SubjectsRequest<'_>) -> Result<Vec<SubjectRef>, QueryError> {
        Ok(match request.resource.attrs.get(&self.attr) {
            Some(Value::Str(owner)) => vec![SubjectRef::User { id: owner.clone() }],
            _ => Vec::new(),
        })
    }
}

/// Allows everything for whoever has `key` on the resource (an `org.manage`, for example). The
/// check for `key` runs without overrides, so there is no recursion.
#[derive(Debug, Clone)]
pub struct PermissionHolder {
    key: String,
    name: String,
}

impl PermissionHolder {
    pub fn new(key: impl Into<String>) -> Self {
        let key = key.into();
        let name = format!("holder:{key}");
        Self { key, name }
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

impl Override for PermissionHolder {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, engine: &Engine, ctx: &Context<'_>, request: &Request<'_>) -> Option<Effect> {
        let probe = Request {
            permission: &self.key,
            ..*request
        };
        engine
            .decide_without_overrides(ctx, &probe)
            .is_allowed()
            .then_some(Effect::Allow)
    }

    fn reach(&self, request: &ReachRequest<'_>) -> OverrideReach {
        OverrideReach::Allows(OverrideGate::Holds(Box::new(request.holds(&self.key))))
    }

    fn subjects(&self, request: &SubjectsRequest<'_>) -> Result<Vec<SubjectRef>, QueryError> {
        request.holders(&self.key)
    }
}

/// Override built from a closure.
pub struct FnOverride<F> {
    name: String,
    f: F,
}

impl<F> FnOverride<F>
where
    F: Fn(&Request<'_>) -> Option<Effect> + Send + Sync,
{
    pub fn new(name: impl Into<String>, f: F) -> Self {
        Self { name: name.into(), f }
    }
}

impl<F> Override for FnOverride<F>
where
    F: Fn(&Request<'_>) -> Option<Effect> + Send + Sync,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _: &Engine, _: &Context<'_>, request: &Request<'_>) -> Option<Effect> {
        (self.f)(request)
    }
}
