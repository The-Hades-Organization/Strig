//! Posse exclusiva de recurso (`strig::ExclusiveRegistry`) sobre um armazenamento em memória.
//! O tempo é sempre um parâmetro, em milissegundos UTC; quem chama é quem confere o relógio.

use serde::Deserialize;
use serde_json::Value;
use strig::{
    Acquisition, Context, ExclusivePermissions, ExclusiveRegistry, MemoryExclusiveStore, ObjectRef, Resource, Subject,
    Terms,
};

use crate::error::{BindingError, BindingResult};
use crate::{ContextData, EngineHandle, parse, to_value};

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExclusiveOptions {
    /// Teto do prazo de uma posse, em milissegundos.
    #[serde(default)]
    max_ttl_ms: Option<u64>,
    /// Nomes das permissões de posse e de preempção no catálogo.
    #[serde(default)]
    permissions: Option<PermissionNames>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionNames {
    hold: String,
    preempt: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TermsInput {
    priority: i64,
    ttl_ms: u64,
}

pub struct ExclusiveHandle {
    registry: ExclusiveRegistry<MemoryExclusiveStore>,
}

impl ExclusiveHandle {
    pub fn new(options: Option<Value>) -> BindingResult<Self> {
        let options: ExclusiveOptions = match options {
            Some(v) if !v.is_null() => parse("options", v)?,
            _ => ExclusiveOptions::default(),
        };
        let mut registry = ExclusiveRegistry::default();
        if let Some(names) = options.permissions {
            registry = registry.with_permissions(ExclusivePermissions {
                hold: names.hold,
                preempt: names.preempt,
            });
        }
        if let Some(max_ttl) = options.max_ttl_ms {
            registry = registry.with_max_ttl(max_ttl);
        }
        Ok(Self { registry })
    }

    /// Confere que o catálogo declara as duas permissões. Falha com `EXCLUSIVE_UNKNOWN_PERMISSION`.
    pub fn validate(&self, engine: &EngineHandle) -> BindingResult<()> {
        Ok(self.registry.validate(engine.engine())?)
    }

    /// Pede a posse de `resource` para `subject`: exige a permissão de posse e, para tomar de um
    /// holder de prioridade menor, a de preempção. Devolve `{ outcome, lease?, previous?, holder? }`
    /// com `outcome` em `granted`, `preempted` (`previous` é a posse tomada, a avisar) ou `busy`
    /// (`holder` é quem segura). Sem a permissão falha com `EXCLUSIVE_DENIED`.
    pub fn acquire(
        &mut self,
        engine: &EngineHandle,
        ctx: &ContextData,
        subject: Value,
        resource: Value,
        terms: Value,
        now: u64,
    ) -> BindingResult<Value> {
        let subject: Subject = parse("subject", subject)?;
        let resource: Resource = parse("resource", resource)?;
        let terms: TermsInput = parse("terms", terms)?;
        // A permissão vale no mesmo instante da posse, não no `now` que o contexto guardou antes.
        let data: Context<'_> = ctx.context().at(now);
        let outcome = self.registry.acquire_checked(
            engine.engine(),
            &data,
            &subject,
            &resource,
            Terms::new(terms.priority, terms.ttl_ms),
            now,
        )?;
        let target = resource.primary().and_then(|anchor| anchor.object_ref());
        Ok(match outcome {
            Acquisition::Granted => out!({"outcome": "granted", "lease": self.lease_of(target, now)?}),
            Acquisition::Preempted { previous } => {
                out!({"outcome": "preempted", "lease": self.lease_of(target, now)?, "previous": previous})
            }
            Acquisition::Busy { holder } => out!({"outcome": "busy", "holder": holder}),
            _ => return Err(BindingError::unsupported("acquire")),
        })
    }

    fn lease_of(&self, target: Option<ObjectRef>, now: u64) -> BindingResult<Value> {
        let Some(target) = target else {
            return Ok(Value::Null);
        };
        Ok(to_value(&self.registry.holder(&target, now)?))
    }

    /// A posse ativa do recurso, ou `null`.
    pub fn holder(&self, resource: Value, now: u64) -> BindingResult<Value> {
        let resource: ObjectRef = parse("resource", resource)?;
        Ok(to_value(&self.registry.holder(&resource, now)?))
    }

    /// Libera o recurso; só o holder pode. Quem chama responde por `holder`.
    pub fn release(&mut self, resource: Value, holder: Value, now: u64) -> BindingResult<Value> {
        let resource: ObjectRef = parse("resource", resource)?;
        let holder: ObjectRef = parse("holder", holder)?;
        Ok(to_value(&self.registry.release(&resource, &holder, now)?))
    }

    /// Estende a posse de `subject` para `now + ttl_ms`, mantendo a prioridade. Confere no
    /// instante `now` a permissão de posse: quem a perdeu não renova, e falha com
    /// `EXCLUSIVE_DENIED` sem mexer na posse. `release` não confere nada, porque largar a posse é
    /// sempre seguro.
    pub fn renew(
        &mut self,
        engine: &EngineHandle,
        ctx: &ContextData,
        subject: Value,
        resource: Value,
        ttl_ms: u64,
        now: u64,
    ) -> BindingResult<Value> {
        let subject: Subject = parse("subject", subject)?;
        let resource: Resource = parse("resource", resource)?;
        // O núcleo troca o instante do contexto por `now` ao conferir a permissão.
        let data: Context<'_> = ctx.context();
        Ok(to_value(&self.registry.renew_checked(
            engine.engine(),
            &data,
            &subject,
            &resource,
            now,
            ttl_ms,
        )?))
    }

    /// Remove e devolve as posses que venceram.
    pub fn expire(&mut self, now: u64) -> BindingResult<Value> {
        Ok(to_value(&self.registry.expire(now)?))
    }
}

/// `ttl_ms` que veio de um número JavaScript.
#[cfg(any(feature = "napi", feature = "wasm", feature = "dsl"))]
pub fn ttl(value: &Value) -> BindingResult<u64> {
    crate::millis_value("ttlMs", value)
}
