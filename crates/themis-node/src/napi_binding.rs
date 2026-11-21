use napi::{Error, Result};
use napi_derive::napi;
use serde_json::Value;

use crate::{ContextData, EngineHandle};

fn err(message: String) -> Error {
    Error::from_reason(message)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
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
}

#[napi]
pub fn audit_estimate(level: Value, records: f64) -> Result<f64> {
    crate::audit_estimate(level, records).map_err(err)
}

#[napi]
pub fn backend() -> &'static str {
    "native"
}
