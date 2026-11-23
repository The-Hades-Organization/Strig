use serde::Serialize;
use serde_json::Value;
use wasm_bindgen::prelude::*;

use crate::{BindingError, ContextData, EngineHandle, ExclusiveHandle};

/// Um `Error` do JavaScript com o `code` estável do binding.
type JsFailure = JsValue;

fn err(error: BindingError) -> JsFailure {
    let failure = js_sys::Error::new(&error.message);
    // Definir uma propriedade num objeto novo e extensível não falha; se falhasse, o erro sairia
    // sem `code`, mas ainda com a mensagem.
    js_sys::Reflect::set(&failure, &JsValue::from_str("code"), &JsValue::from_str(error.code)).ok();
    failure.into()
}

fn from_js(value: JsValue) -> Result<Value, JsFailure> {
    serde_wasm_bindgen::from_value(value).map_err(|e| err(BindingError::invalid_input("argumento", e)))
}

fn to_js(value: &Value) -> Result<JsValue, JsFailure> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| err(BindingError::new("INTERNAL", e.to_string())))
}

fn optional(value: JsValue) -> Result<Option<Value>, JsFailure> {
    if value.is_undefined() || value.is_null() {
        Ok(None)
    } else {
        from_js(value).map(Some)
    }
}

/// O instante da chamada: o do argumento, ou o relógio do navegador.
fn instant(now: Option<f64>) -> Result<u64, JsFailure> {
    crate::millis("now", now.unwrap_or_else(js_sys::Date::now)).map_err(err)
}

#[wasm_bindgen(js_name = Context)]
pub struct WasmContext {
    inner: ContextData,
}

#[wasm_bindgen(js_class = Context)]
impl WasmContext {
    #[wasm_bindgen(constructor)]
    pub fn new(init: JsValue) -> Result<WasmContext, JsFailure> {
        Ok(Self {
            inner: ContextData::new(optional(init)?).map_err(err)?,
        })
    }

    #[wasm_bindgen(js_name = setGrants)]
    pub fn set_grants(&mut self, grants: JsValue) -> Result<(), JsFailure> {
        self.inner.set_grants(from_js(grants)?).map_err(err)
    }

    #[wasm_bindgen(js_name = addGrant)]
    pub fn add_grant(&mut self, grant: JsValue) -> Result<(), JsFailure> {
        self.inner.add_grant(from_js(grant)?).map_err(err)
    }

    #[wasm_bindgen(js_name = removeGrant)]
    pub fn remove_grant(&mut self, id: &str) -> bool {
        self.inner.remove_grant(id)
    }

    pub fn grants(&self) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.grants())
    }

    #[wasm_bindgen(getter)]
    pub fn size(&self) -> u32 {
        self.inner.grant_count() as u32
    }

    #[wasm_bindgen(js_name = addTuple)]
    pub fn add_tuple(&mut self, tuple: JsValue) -> Result<bool, JsFailure> {
        self.inner.add_tuple(from_js(tuple)?).map_err(err)
    }

    #[wasm_bindgen(js_name = removeTuple)]
    pub fn remove_tuple(&mut self, tuple: JsValue) -> Result<bool, JsFailure> {
        self.inner.remove_tuple(from_js(tuple)?).map_err(err)
    }

    #[wasm_bindgen(js_name = setEnv)]
    pub fn set_env(&mut self, env: JsValue) -> Result<(), JsFailure> {
        self.inner.set_env(from_js(env)?).map_err(err)
    }

    #[wasm_bindgen(js_name = loadCapabilities)]
    pub fn load_capabilities(&mut self, set: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.load_capabilities(from_js(set)?).map_err(err)?)
    }

    /// Instante das decisões e das consultas, em milissegundos UTC; `null` o remove.
    #[wasm_bindgen(js_name = setNow)]
    pub fn set_now(&mut self, now: Option<f64>) -> Result<(), JsFailure> {
        self.inner.set_now(now.map_or(Value::Null, Value::from)).map_err(err)
    }

    #[wasm_bindgen(js_name = setLimits)]
    pub fn set_limits(&mut self, limits: JsValue) -> Result<(), JsFailure> {
        self.inner.set_limits(from_js(limits)?).map_err(err)
    }
}

#[wasm_bindgen(js_name = Engine)]
pub struct WasmEngine {
    inner: EngineHandle,
}

#[wasm_bindgen(js_class = Engine)]
impl WasmEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(spec: JsValue) -> Result<WasmEngine, JsFailure> {
        Ok(Self {
            inner: EngineHandle::new(from_js(spec)?).map_err(err)?,
        })
    }

    pub fn decide(&self, ctx: &WasmContext, request: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.decide(&ctx.inner, from_js(request)?).map_err(err)?)
    }

    pub fn check(&self, ctx: &WasmContext, request: JsValue) -> Result<bool, JsFailure> {
        self.inner.check(&ctx.inner, from_js(request)?).map_err(err)
    }

    pub fn explain(&self, ctx: &WasmContext, request: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.explain(&ctx.inner, from_js(request)?).map_err(err)?)
    }

    pub fn capabilities(&self, ctx: &WasmContext, subject: JsValue, scope: JsValue) -> Result<JsValue, JsFailure> {
        let set = self
            .inner
            .capabilities(&ctx.inner, from_js(subject)?, from_js(scope)?)
            .map_err(err)?;
        to_js(&set)
    }

    #[wasm_bindgen(js_name = validateGrant)]
    pub fn validate_grant(&self, grant: JsValue) -> Result<(), JsFailure> {
        self.inner.validate_grant(from_js(grant)?).map_err(err)
    }

    pub fn catalog(&self) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.catalog())
    }

    pub fn apply(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.apply(from_js(input)?, instant(None)?).map_err(err)?)
    }

    pub fn materialize(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.materialize(from_js(input)?).map_err(err)?)
    }

    #[wasm_bindgen(js_name = applyTemplate)]
    pub fn apply_template(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .apply_template(from_js(input)?, instant(None)?)
                .map_err(err)?,
        )
    }

    pub fn list(
        &self,
        ctx: &WasmContext,
        subject: JsValue,
        permission: &str,
        kind: &str,
        options: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let out = self
            .inner
            .list(&ctx.inner, from_js(subject)?, permission, kind, optional(options)?)
            .map_err(err)?;
        to_js(&out)
    }

    #[wasm_bindgen(js_name = whoCan)]
    pub fn who_can(&self, ctx: &WasmContext, permission: &str) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.who_can(&ctx.inner, permission))
    }

    #[wasm_bindgen(js_name = whoCanOn)]
    pub fn who_can_on(&self, ctx: &WasmContext, permission: &str, resource: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .who_can_on(&ctx.inner, permission, from_js(resource)?)
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = accessOf)]
    pub fn access_of(&self, ctx: &WasmContext, resource: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.access_of(&ctx.inner, from_js(resource)?).map_err(err)?)
    }

    #[wasm_bindgen(js_name = checkFor)]
    pub fn check_for(
        &self,
        ctx: &WasmContext,
        subject_ref: JsValue,
        permission: &str,
        resource: JsValue,
        subjects: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let out = self
            .inner
            .check_for(
                &ctx.inner,
                from_js(subject_ref)?,
                permission,
                from_js(resource)?,
                from_js(subjects)?,
            )
            .map_err(err)?;
        to_js(&out)
    }
}

#[wasm_bindgen(js_name = Exclusive)]
pub struct WasmExclusive {
    inner: ExclusiveHandle,
}

#[wasm_bindgen(js_class = Exclusive)]
impl WasmExclusive {
    #[wasm_bindgen(constructor)]
    pub fn new(options: JsValue) -> Result<WasmExclusive, JsFailure> {
        Ok(Self {
            inner: ExclusiveHandle::new(optional(options)?).map_err(err)?,
        })
    }

    pub fn validate(&self, engine: &WasmEngine) -> Result<(), JsFailure> {
        self.inner.validate(&engine.inner).map_err(err)
    }

    pub fn acquire(
        &mut self,
        engine: &WasmEngine,
        ctx: &WasmContext,
        subject: JsValue,
        resource: JsValue,
        terms: JsValue,
        now: Option<f64>,
    ) -> Result<JsValue, JsFailure> {
        let now = instant(now)?;
        let out = self
            .inner
            .acquire(
                &engine.inner,
                &ctx.inner,
                from_js(subject)?,
                from_js(resource)?,
                from_js(terms)?,
                now,
            )
            .map_err(err)?;
        to_js(&out)
    }

    pub fn holder(&self, resource: JsValue, now: Option<f64>) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.holder(from_js(resource)?, instant(now)?).map_err(err)?)
    }

    pub fn release(&mut self, resource: JsValue, holder: JsValue, now: Option<f64>) -> Result<JsValue, JsFailure> {
        let out = self
            .inner
            .release(from_js(resource)?, from_js(holder)?, instant(now)?)
            .map_err(err)?;
        to_js(&out)
    }

    pub fn renew(
        &mut self,
        resource: JsValue,
        holder: JsValue,
        #[wasm_bindgen(js_name = ttlMs)] ttl_ms: f64,
        now: Option<f64>,
    ) -> Result<JsValue, JsFailure> {
        let ttl = crate::exclusive::ttl(ttl_ms).map_err(err)?;
        let out = self
            .inner
            .renew(from_js(resource)?, from_js(holder)?, ttl, instant(now)?)
            .map_err(err)?;
        to_js(&out)
    }

    pub fn expire(&mut self, now: Option<f64>) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.expire(instant(now)?).map_err(err)?)
    }
}

#[wasm_bindgen(js_name = auditEstimate)]
pub fn audit_estimate(level: JsValue, records: f64) -> Result<f64, JsFailure> {
    crate::audit_estimate(from_js(level)?, records).map_err(err)
}

#[wasm_bindgen]
pub fn backend() -> String {
    "wasm".to_string()
}
