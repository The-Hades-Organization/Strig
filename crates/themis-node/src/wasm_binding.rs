use serde::Serialize;
use serde_json::Value;
use wasm_bindgen::prelude::*;

use crate::{ContextData, EngineHandle};

fn err(message: impl AsRef<str>) -> JsError {
    JsError::new(message.as_ref())
}

fn from_js(value: JsValue) -> Result<Value, JsError> {
    serde_wasm_bindgen::from_value(value).map_err(|e| err(e.to_string()))
}

fn to_js(value: &Value) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| err(e.to_string()))
}

#[wasm_bindgen(js_name = Context)]
pub struct WasmContext {
    inner: ContextData,
}

#[wasm_bindgen(js_class = Context)]
impl WasmContext {
    #[wasm_bindgen(constructor)]
    pub fn new(init: JsValue) -> Result<WasmContext, JsError> {
        let init = if init.is_undefined() || init.is_null() {
            None
        } else {
            Some(from_js(init)?)
        };
        Ok(Self {
            inner: ContextData::new(init).map_err(err)?,
        })
    }

    #[wasm_bindgen(js_name = setGrants)]
    pub fn set_grants(&mut self, grants: JsValue) -> Result<(), JsError> {
        self.inner.set_grants(from_js(grants)?).map_err(err)
    }

    #[wasm_bindgen(js_name = addGrant)]
    pub fn add_grant(&mut self, grant: JsValue) -> Result<(), JsError> {
        self.inner.add_grant(from_js(grant)?).map_err(err)
    }

    #[wasm_bindgen(js_name = removeGrant)]
    pub fn remove_grant(&mut self, id: &str) -> bool {
        self.inner.remove_grant(id)
    }

    pub fn grants(&self) -> Result<JsValue, JsError> {
        to_js(&self.inner.grants())
    }

    #[wasm_bindgen(getter)]
    pub fn size(&self) -> u32 {
        self.inner.grant_count() as u32
    }

    #[wasm_bindgen(js_name = addTuple)]
    pub fn add_tuple(&mut self, tuple: JsValue) -> Result<bool, JsError> {
        self.inner.add_tuple(from_js(tuple)?).map_err(err)
    }

    #[wasm_bindgen(js_name = removeTuple)]
    pub fn remove_tuple(&mut self, tuple: JsValue) -> Result<bool, JsError> {
        self.inner.remove_tuple(from_js(tuple)?).map_err(err)
    }

    #[wasm_bindgen(js_name = setEnv)]
    pub fn set_env(&mut self, env: JsValue) -> Result<(), JsError> {
        self.inner.set_env(from_js(env)?).map_err(err)
    }

    #[wasm_bindgen(js_name = loadCapabilities)]
    pub fn load_capabilities(&mut self, set: JsValue) -> Result<JsValue, JsError> {
        to_js(&self.inner.load_capabilities(from_js(set)?).map_err(err)?)
    }
}

#[wasm_bindgen(js_name = Engine)]
pub struct WasmEngine {
    inner: EngineHandle,
}

#[wasm_bindgen(js_class = Engine)]
impl WasmEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(spec: JsValue) -> Result<WasmEngine, JsError> {
        Ok(Self {
            inner: EngineHandle::new(from_js(spec)?).map_err(err)?,
        })
    }

    pub fn decide(&self, ctx: &WasmContext, request: JsValue) -> Result<JsValue, JsError> {
        to_js(&self.inner.decide(&ctx.inner, from_js(request)?).map_err(err)?)
    }

    pub fn check(&self, ctx: &WasmContext, request: JsValue) -> Result<bool, JsError> {
        self.inner.check(&ctx.inner, from_js(request)?).map_err(err)
    }

    pub fn capabilities(&self, ctx: &WasmContext, subject: JsValue, scope: JsValue) -> Result<JsValue, JsError> {
        let set = self
            .inner
            .capabilities(&ctx.inner, from_js(subject)?, from_js(scope)?)
            .map_err(err)?;
        to_js(&set)
    }

    #[wasm_bindgen(js_name = validateGrant)]
    pub fn validate_grant(&self, grant: JsValue) -> Result<(), JsError> {
        self.inner.validate_grant(from_js(grant)?).map_err(err)
    }

    pub fn catalog(&self) -> Result<JsValue, JsError> {
        to_js(&self.inner.catalog())
    }

    pub fn apply(&self, input: JsValue) -> Result<JsValue, JsError> {
        let now = js_sys::Date::now() as u64;
        to_js(&self.inner.apply(from_js(input)?, now).map_err(err)?)
    }
}

#[wasm_bindgen(js_name = auditEstimate)]
pub fn audit_estimate(level: JsValue, records: f64) -> Result<f64, JsError> {
    crate::audit_estimate(from_js(level)?, records).map_err(err)
}

#[wasm_bindgen]
pub fn backend() -> String {
    "wasm".to_string()
}
