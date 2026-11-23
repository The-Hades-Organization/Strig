use napi_derive::napi;
use serde_json::Value;

use crate::{BindingError, ContextData, EngineHandle, ExclusiveHandle};

/// O `code` estável do erro vira `error.code` no JavaScript.
type Error = napi::Error<String>;
type Result<T> = std::result::Result<T, Error>;

fn err(error: BindingError) -> Error {
    Error::new(error.code.to_string(), error.message)
}

/// O instante da chamada: o do argumento, ou o relógio do sistema.
fn instant(now: Option<f64>) -> Result<u64> {
    match now {
        Some(ms) => crate::millis("now", ms).map_err(err),
        None => Ok(now_ms()),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[napi(js_name = "Context")]
pub struct JsContext {
    inner: ContextData,
}

#[napi]
impl JsContext {
    #[napi(constructor)]
    pub fn new(init: Option<Value>) -> Result<Self> {
        Ok(Self {
            inner: ContextData::new(init).map_err(err)?,
        })
    }

    #[napi]
    pub fn set_grants(&mut self, grants: Value) -> Result<()> {
        self.inner.set_grants(grants).map_err(err)
    }

    #[napi]
    pub fn add_grant(&mut self, grant: Value) -> Result<()> {
        self.inner.add_grant(grant).map_err(err)
    }

    #[napi]
    pub fn remove_grant(&mut self, id: String) -> bool {
        self.inner.remove_grant(&id)
    }

    #[napi]
    pub fn grants(&self) -> Value {
        self.inner.grants()
    }

    #[napi(getter)]
    pub fn size(&self) -> u32 {
        self.inner.grant_count() as u32
    }

    #[napi]
    pub fn add_tuple(&mut self, tuple: Value) -> Result<bool> {
        self.inner.add_tuple(tuple).map_err(err)
    }

    #[napi]
    pub fn remove_tuple(&mut self, tuple: Value) -> Result<bool> {
        self.inner.remove_tuple(tuple).map_err(err)
    }

    #[napi]
    pub fn set_env(&mut self, env: Value) -> Result<()> {
        self.inner.set_env(env).map_err(err)
    }

    #[napi]
    pub fn load_capabilities(&mut self, set: Value) -> Result<Value> {
        self.inner.load_capabilities(set).map_err(err)
    }

    /// Instante das decisões e das consultas, em milissegundos UTC; `null` o remove.
    #[napi]
    pub fn set_now(&mut self, now: Option<f64>) -> Result<()> {
        self.inner.set_now(now.map_or(Value::Null, Value::from)).map_err(err)
    }

    #[napi]
    pub fn set_limits(&mut self, limits: Value) -> Result<()> {
        self.inner.set_limits(limits).map_err(err)
    }
}

#[napi(js_name = "Engine")]
pub struct JsEngine {
    inner: EngineHandle,
}

#[napi]
impl JsEngine {
    #[napi(constructor)]
    pub fn new(spec: Value) -> Result<Self> {
        Ok(Self {
            inner: EngineHandle::new(spec).map_err(err)?,
        })
    }

    #[napi]
    pub fn decide(&self, ctx: &JsContext, request: Value) -> Result<Value> {
        self.inner.decide(&ctx.inner, request).map_err(err)
    }

    #[napi]
    pub fn check(&self, ctx: &JsContext, request: Value) -> Result<bool> {
        self.inner.check(&ctx.inner, request).map_err(err)
    }

    #[napi]
    pub fn explain(&self, ctx: &JsContext, request: Value) -> Result<Value> {
        self.inner.explain(&ctx.inner, request).map_err(err)
    }

    #[napi]
    pub fn capabilities(&self, ctx: &JsContext, subject: Value, scope: Value) -> Result<Value> {
        self.inner.capabilities(&ctx.inner, subject, scope).map_err(err)
    }

    #[napi]
    pub fn validate_grant(&self, grant: Value) -> Result<()> {
        self.inner.validate_grant(grant).map_err(err)
    }

    #[napi]
    pub fn catalog(&self) -> Value {
        self.inner.catalog()
    }

    #[napi]
    pub fn apply(&self, input: Value) -> Result<Value> {
        self.inner.apply(input, now_ms()).map_err(err)
    }

    #[napi]
    pub fn materialize(&self, input: Value) -> Result<Value> {
        self.inner.materialize(input).map_err(err)
    }

    #[napi]
    pub fn apply_template(&self, input: Value) -> Result<Value> {
        self.inner.apply_template(input, now_ms()).map_err(err)
    }

    #[napi]
    pub fn list(
        &self,
        ctx: &JsContext,
        subject: Value,
        permission: String,
        kind: String,
        options: Option<Value>,
    ) -> Result<Value> {
        self.inner
            .list(&ctx.inner, subject, &permission, &kind, options)
            .map_err(err)
    }

    #[napi]
    pub fn who_can(&self, ctx: &JsContext, permission: String) -> Value {
        self.inner.who_can(&ctx.inner, &permission)
    }

    #[napi]
    pub fn who_can_on(&self, ctx: &JsContext, permission: String, resource: Value) -> Result<Value> {
        self.inner
            .who_can_on(&ctx.inner, &permission, resource)
            .map_err(err)
    }

    #[napi]
    pub fn access_of(&self, ctx: &JsContext, resource: Value) -> Result<Value> {
        self.inner.access_of(&ctx.inner, resource).map_err(err)
    }

    #[napi]
    pub fn check_for(
        &self,
        ctx: &JsContext,
        subject_ref: Value,
        permission: String,
        resource: Value,
        subjects: Value,
    ) -> Result<Value> {
        self.inner
            .check_for(&ctx.inner, subject_ref, &permission, resource, subjects)
            .map_err(err)
    }
}

#[napi(js_name = "Exclusive")]
pub struct JsExclusive {
    inner: ExclusiveHandle,
}

#[napi]
impl JsExclusive {
    #[napi(constructor)]
    pub fn new(options: Option<Value>) -> Result<Self> {
        Ok(Self {
            inner: ExclusiveHandle::new(options).map_err(err)?,
        })
    }

    #[napi]
    pub fn validate(&self, engine: &JsEngine) -> Result<()> {
        self.inner.validate(&engine.inner).map_err(err)
    }

    #[napi]
    pub fn acquire(
        &mut self,
        engine: &JsEngine,
        ctx: &JsContext,
        subject: Value,
        resource: Value,
        terms: Value,
        now: Option<f64>,
    ) -> Result<Value> {
        let now = instant(now)?;
        self.inner
            .acquire(&engine.inner, &ctx.inner, subject, resource, terms, now)
            .map_err(err)
    }

    #[napi]
    pub fn holder(&self, resource: Value, now: Option<f64>) -> Result<Value> {
        self.inner.holder(resource, instant(now)?).map_err(err)
    }

    #[napi]
    pub fn release(&mut self, resource: Value, holder: Value, now: Option<f64>) -> Result<Value> {
        self.inner.release(resource, holder, instant(now)?).map_err(err)
    }

    #[napi]
    pub fn renew(&mut self, resource: Value, holder: Value, ttl_ms: f64, now: Option<f64>) -> Result<Value> {
        let ttl = crate::exclusive::ttl(ttl_ms).map_err(err)?;
        self.inner.renew(resource, holder, ttl, instant(now)?).map_err(err)
    }

    #[napi]
    pub fn expire(&mut self, now: Option<f64>) -> Result<Value> {
        self.inner.expire(instant(now)?).map_err(err)
    }
}

#[napi]
pub fn audit_estimate(level: Value, records: f64) -> Result<f64> {
    crate::audit_estimate(level, records).map_err(err)
}

#[napi]
pub fn backend() -> &'static str {
    "native"
}
