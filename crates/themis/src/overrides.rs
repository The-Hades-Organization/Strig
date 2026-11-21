use crate::attr::Value;
use crate::decision::Request;
use crate::engine::{Context, Engine};
use crate::grant::Effect;

/// Decide antes dos grants. Serve para dono do recurso, superadmin, conta suspensa.
///
/// O motor consulta os overrides em ordem e para no primeiro que devolver `Some`. Exceções
/// por permissão são configuradas no [`crate::EngineBuilder::override_except`].
pub trait Override: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, engine: &Engine, ctx: &Context<'_>, request: &Request<'_>) -> Option<Effect>;
}

/// Libera tudo para o sujeito cujo id está no atributo `attr` do recurso.
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

/// Libera tudo para quem tem `key` sobre o recurso (um `org.manage`, por exemplo). A checagem
/// de `key` roda sem overrides, então não há recursão.
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

/// Override a partir de uma closure.
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
