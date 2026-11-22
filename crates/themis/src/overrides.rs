use crate::attr::Value;
use crate::decision::Request;
use crate::engine::{Context, Engine};
use crate::grant::Effect;

/// Decides before the grants. Meant for the resource owner, superadmin, suspended account.
///
/// The engine consults the overrides in order and stops at the first one that returns `Some`.
/// Per-permission exceptions are configured in [`crate::EngineBuilder::override_except`].
pub trait Override: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, engine: &Engine, ctx: &Context<'_>, request: &Request<'_>) -> Option<Effect>;
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
