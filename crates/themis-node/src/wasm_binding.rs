use serde::Serialize;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
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

/// Um valor JavaScript em `serde_json::Value` que recusa o que não é JSON: `NaN` e `±Infinity`
/// viram erro, em vez de `null` (que é o que o `Value` faz com um float não finito e que, num
/// `now`, apagaria o instante).
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Walk;

        impl<'de> Visitor<'de> for Walk {
            type Value = Strict;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("um valor JSON")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }

            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Strict, E> {
                if v.is_finite() {
                    Ok(Strict(Value::from(v)))
                } else {
                    Err(E::custom("número não finito (NaN ou Infinity)"))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.to_string())))
            }

            fn visit_string<E>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }

            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }

            fn visit_none<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }

            fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Strict, D::Error> {
                Strict::deserialize(deserializer)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut items = Vec::new();
                while let Some(Strict(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Strict(Value::Array(items)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut fields = Map::new();
                while let Some((key, Strict(value))) = map.next_entry::<String, Strict>()? {
                    fields.insert(key, value);
                }
                Ok(Strict(Value::Object(fields)))
            }
        }

        deserializer.deserialize_any(Walk)
    }
}

fn from_js(value: JsValue) -> Result<Value, JsFailure> {
    Strict::deserialize(serde_wasm_bindgen::Deserializer::from(value))
        .map(|strict| strict.0)
        .map_err(|e| err(BindingError::invalid_argument("argumento", e)))
}

/// Um argumento de texto: qualquer outro tipo é `INVALID_ARGUMENT`, nunca coagido.
fn text(what: &str, value: &JsValue) -> Result<String, JsFailure> {
    value
        .as_string()
        .ok_or_else(|| err(BindingError::invalid_argument(what, "esperado um texto")))
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

/// O `now` opcional de uma chamada: `undefined` e `null` são "sem instante"; qualquer outra coisa
/// que não seja um inteiro em milissegundos é `INVALID_ARGUMENT`.
fn now_of(now: JsValue) -> Result<Option<u64>, JsFailure> {
    crate::now_arg(optional(now)?).map_err(err)
}

/// O instante da chamada: o do argumento, ou o relógio do navegador.
fn instant(now: JsValue) -> Result<u64, JsFailure> {
    match now_of(now)? {
        Some(ms) => Ok(ms),
        None => crate::millis("now", js_sys::Date::now()).map_err(err),
    }
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
    pub fn remove_grant(&mut self, id: JsValue) -> Result<bool, JsFailure> {
        Ok(self.inner.remove_grant(&text("id", &id)?))
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
    pub fn set_now(&mut self, now: JsValue) -> Result<(), JsFailure> {
        self.inner.set_now(optional(now)?.unwrap_or(Value::Null)).map_err(err)
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

    pub fn decide(&self, ctx: &WasmContext, request: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .decide(&ctx.inner, from_js(request)?, now_of(now)?)
                .map_err(err)?,
        )
    }

    pub fn check(&self, ctx: &WasmContext, request: JsValue, now: JsValue) -> Result<bool, JsFailure> {
        self.inner
            .check(&ctx.inner, from_js(request)?, now_of(now)?)
            .map_err(err)
    }

    pub fn explain(&self, ctx: &WasmContext, request: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .explain(&ctx.inner, from_js(request)?, now_of(now)?)
                .map_err(err)?,
        )
    }

    pub fn capabilities(
        &self,
        ctx: &WasmContext,
        subject: JsValue,
        scope: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let set = self
            .inner
            .capabilities(&ctx.inner, from_js(subject)?, from_js(scope)?, now_of(now)?)
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
        to_js(
            &self
                .inner
                .apply(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    pub fn materialize(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.materialize(from_js(input)?).map_err(err)?)
    }

    #[wasm_bindgen(js_name = applyTemplate)]
    pub fn apply_template(&self, input: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .apply_template(from_js(input)?, crate::millis("now", js_sys::Date::now()))
                .map_err(err)?,
        )
    }

    pub fn list(
        &self,
        ctx: &WasmContext,
        subject: JsValue,
        permission: JsValue,
        kind: JsValue,
        options: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let out = self
            .inner
            .list(
                &ctx.inner,
                from_js(subject)?,
                &text("permission", &permission)?,
                &text("kind", &kind)?,
                optional(options)?,
                now_of(now)?,
            )
            .map_err(err)?;
        to_js(&out)
    }

    #[wasm_bindgen(js_name = whoCan)]
    pub fn who_can(&self, ctx: &WasmContext, permission: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .who_can(&ctx.inner, &text("permission", &permission)?, now_of(now)?),
        )
    }

    #[wasm_bindgen(js_name = whoCanOn)]
    pub fn who_can_on(
        &self,
        ctx: &WasmContext,
        permission: JsValue,
        resource: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .who_can_on(
                    &ctx.inner,
                    &text("permission", &permission)?,
                    from_js(resource)?,
                    now_of(now)?,
                )
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = accessOf)]
    pub fn access_of(&self, ctx: &WasmContext, resource: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(
            &self
                .inner
                .access_of(&ctx.inner, from_js(resource)?, now_of(now)?)
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = checkFor)]
    pub fn check_for(
        &self,
        ctx: &WasmContext,
        subject_ref: JsValue,
        permission: JsValue,
        resource: JsValue,
        subjects: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let out = self
            .inner
            .check_for(
                &ctx.inner,
                from_js(subject_ref)?,
                &text("permission", &permission)?,
                from_js(resource)?,
                from_js(subjects)?,
                now_of(now)?,
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
        now: JsValue,
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

    pub fn holder(&self, resource: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.holder(from_js(resource)?, instant(now)?).map_err(err)?)
    }

    pub fn release(&mut self, resource: JsValue, holder: JsValue, now: JsValue) -> Result<JsValue, JsFailure> {
        let out = self
            .inner
            .release(from_js(resource)?, from_js(holder)?, instant(now)?)
            .map_err(err)?;
        to_js(&out)
    }

    pub fn renew(
        &mut self,
        engine: &WasmEngine,
        ctx: &WasmContext,
        subject: JsValue,
        resource: JsValue,
        #[wasm_bindgen(js_name = ttlMs)] ttl_ms: JsValue,
        now: JsValue,
    ) -> Result<JsValue, JsFailure> {
        let ttl = crate::exclusive::ttl(&from_js(ttl_ms)?).map_err(err)?;
        let now = instant(now)?;
        let out = self
            .inner
            .renew(
                &engine.inner,
                &ctx.inner,
                from_js(subject)?,
                from_js(resource)?,
                ttl,
                now,
            )
            .map_err(err)?;
        to_js(&out)
    }

    pub fn expire(&mut self, now: JsValue) -> Result<JsValue, JsFailure> {
        to_js(&self.inner.expire(instant(now)?).map_err(err)?)
    }
}

#[wasm_bindgen(js_name = auditEstimate)]
pub fn audit_estimate(level: JsValue, records: JsValue) -> Result<f64, JsFailure> {
    crate::audit_estimate(from_js(level)?, from_js(records)?).map_err(err)
}

#[wasm_bindgen]
pub fn backend() -> String {
    "wasm".to_string()
}
