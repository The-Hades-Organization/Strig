//! Bindings JavaScript da Themis.
//!
//! O núcleo ([`EngineHandle`], [`ContextData`]) recebe e devolve `serde_json::Value` e é o
//! mesmo nos dois alvos. `napi` gera o módulo nativo para Node e Bun; `wasm` gera o
//! WebAssembly para o navegador. O pacote npm em `js/` escolhe o alvo em tempo de execução.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};
use themis::audit::{AuditLevel, Auditor, MemoryAuditLog};
use themis::{
    Attributes, CapabilitySet, Context, Engine, EngineSpec, Governance, Grant, InMemoryTuples, InvariantSpec, Mutation,
    Request, Resource, Subject, Tuple,
};

#[cfg(feature = "napi")]
mod napi_binding;
#[cfg(feature = "wasm")]
mod wasm_binding;

pub type BindingResult<T> = Result<T, String>;

fn parse<T: for<'de> Deserialize<'de>>(what: &str, value: Value) -> BindingResult<T> {
    serde_json::from_value(value).map_err(|e| format!("{what} inválido: {e}"))
}

fn to_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("tipos da Themis sempre serializam")
}

/// Grants, tuplas e ambiente de uma decisão, mantidos do lado Rust para não converter a
/// cada chamada.
#[derive(Default)]
pub struct ContextData {
    grants: Vec<Grant>,
    tuples: InMemoryTuples,
    env: Attributes,
    with_tuples: bool,
}

impl ContextData {
    pub fn new(init: Option<Value>) -> BindingResult<Self> {
        let mut data = Self::default();
        let Some(Value::Object(init)) = init else {
            return Ok(data);
        };
        if let Some(grants) = init.get("grants") {
            data.set_grants(grants.clone())?;
        }
        if let Some(tuples) = init.get("tuples") {
            for tuple in parse::<Vec<Tuple>>("tuples", tuples.clone())? {
                data.tuples.insert(tuple);
            }
            data.with_tuples = true;
        }
        if let Some(env) = init.get("env") {
            data.set_env(env.clone())?;
        }
        Ok(data)
    }

    pub fn set_grants(&mut self, grants: Value) -> BindingResult<()> {
        self.grants = parse("grants", grants)?;
        Ok(())
    }

    pub fn add_grant(&mut self, grant: Value) -> BindingResult<()> {
        let grant: Grant = parse("grant", grant)?;
        self.grants.retain(|g| g.id != grant.id);
        self.grants.push(grant);
        Ok(())
    }

    pub fn remove_grant(&mut self, id: &str) -> bool {
        let before = self.grants.len();
        self.grants.retain(|g| g.id != id);
        before != self.grants.len()
    }

    pub fn grants(&self) -> Value {
        to_value(&self.grants)
    }

    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    pub fn add_tuple(&mut self, tuple: Value) -> BindingResult<bool> {
        self.with_tuples = true;
        Ok(self.tuples.insert(parse("tuple", tuple)?))
    }

    pub fn remove_tuple(&mut self, tuple: Value) -> BindingResult<bool> {
        Ok(self.tuples.remove(&parse("tuple", tuple)?))
    }

    pub fn set_env(&mut self, env: Value) -> BindingResult<()> {
        self.env = parse("env", env)?;
        Ok(())
    }

    /// Troca os grants pelos de um `CapabilitySet` recebido do servidor.
    pub fn load_capabilities(&mut self, set: Value) -> BindingResult<Value> {
        let set: CapabilitySet = parse("capabilities", set)?;
        self.grants = set.grants;
        Ok(to_value(&set.subject))
    }

    fn context(&self) -> Context<'_> {
        let ctx = Context::new(&self.grants).with_env(&self.env);
        if self.with_tuples {
            ctx.with_tuples(&self.tuples)
        } else {
            ctx
        }
    }
}

#[derive(Deserialize)]
struct RequestInput {
    subject: Subject,
    permission: String,
    resource: Resource,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditInput {
    level: AuditLevel,
    #[serde(default)]
    prev_hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyInput {
    actor: Subject,
    current: Vec<Grant>,
    mutation: Mutation,
    #[serde(default)]
    invariants: Vec<InvariantSpec>,
    #[serde(default)]
    tuples: Option<Vec<Tuple>>,
    #[serde(default)]
    audit: Option<AuditInput>,
    #[serde(default)]
    meta: Attributes,
}

pub struct EngineHandle {
    engine: Engine,
}

impl EngineHandle {
    pub fn new(spec: Value) -> BindingResult<Self> {
        let spec: EngineSpec = parse("spec", spec)?;
        let engine = spec.build().map_err(|e| e.to_string())?;
        Ok(Self { engine })
    }

    pub fn decide(&self, ctx: &ContextData, request: Value) -> BindingResult<Value> {
        let input: RequestInput = parse("request", request)?;
        let request = Request::new(&input.subject, &input.permission, &input.resource);
        Ok(to_value(&self.engine.decide(&ctx.context(), &request)))
    }

    pub fn check(&self, ctx: &ContextData, request: Value) -> BindingResult<bool> {
        let input: RequestInput = parse("request", request)?;
        let request = Request::new(&input.subject, &input.permission, &input.resource);
        Ok(self.engine.check(&ctx.context(), &request))
    }

    /// A decisão com o rastro completo (`themis::Explanation`).
    pub fn explain(&self, ctx: &ContextData, request: Value) -> BindingResult<Value> {
        let input: RequestInput = parse("request", request)?;
        let request = Request::new(&input.subject, &input.permission, &input.resource);
        Ok(to_value(&self.engine.explain(&ctx.context(), &request)))
    }

    pub fn capabilities(&self, ctx: &ContextData, subject: Value, scope: Value) -> BindingResult<Value> {
        let subject: Subject = parse("subject", subject)?;
        let scope: Resource = parse("scope", scope)?;
        Ok(to_value(&self.engine.capabilities(&ctx.context(), &subject, &scope)))
    }

    pub fn validate_grant(&self, grant: Value) -> BindingResult<()> {
        let grant: Grant = parse("grant", grant)?;
        self.engine.validate_grant(&grant).map_err(|e| e.to_string())
    }

    pub fn catalog(&self) -> Value {
        to_value(&self.engine.catalog().export())
    }

    /// Aplica uma mudança de grant ou de papel pelos invariantes. Devolve
    /// `{ ok, grants?, subject?, violations?, audit? }`; `subject` é o sujeito com o papel
    /// aplicado, numa mudança de papel aceita, e `audit` é o registro a gravar quando a entrada
    /// pede auditoria.
    pub fn apply(&self, input: Value, now_ms: u64) -> BindingResult<Value> {
        let input: ApplyInput = parse("apply", input)?;
        let governance: Governance = input.invariants.iter().collect();
        let log = Arc::new(MemoryAuditLog::new());
        let governance = match &input.audit {
            Some(audit) => {
                let mut auditor = Auditor::new(audit.level, log.clone()).with_clock(move || now_ms);
                if let Some(prev) = &audit.prev_hash {
                    auditor = auditor.resume_chain(prev.clone());
                }
                governance.audited(Arc::new(auditor))
            }
            None => governance,
        };
        let store: Option<InMemoryTuples> = input.tuples.map(|t| t.into_iter().collect());
        let tuples = store.as_ref().map(|s| s as &dyn themis::TupleStore);
        let result = governance.apply_with(
            &self.engine,
            &input.actor,
            &input.current,
            &input.mutation,
            tuples,
            &input.meta,
        );
        let audit = log.drain().pop().map(|r| to_value(&r));
        Ok(match result {
            Ok(grants) => {
                let mut out = json!({ "ok": true, "grants": grants, "audit": audit });
                if let Some(subject) = input.mutation.subject_after() {
                    out["subject"] = to_value(&subject);
                }
                out
            }
            Err(violations) => json!({ "ok": false, "violations": violations, "audit": audit }),
        })
    }
}

/// Bytes estimados para `records` registros de auditoria no nível dado.
pub fn audit_estimate(level: Value, records: f64) -> BindingResult<f64> {
    let level: AuditLevel = parse("level", level)?;
    Ok(level.estimate_bytes(records.max(0.0) as u64) as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> Value {
        json!({
            "catalog": {
                "targetKinds": ["project"],
                "broadTargets": ["org"],
                "permissions": [
                    {"key": "project.view", "targets": ["project"]},
                    {"key": "project.edit", "targets": ["project"]}
                ]
            }
        })
    }

    #[test]
    fn decide_and_apply_through_json() {
        let engine = EngineHandle::new(spec()).unwrap();
        let ctx = ContextData::new(Some(json!({
            "grants": [{"id": "g", "subject": {"kind": "role", "id": "member"}, "permission": "project.view",
                        "target": {"kind": "project"}, "effect": "allow"}]
        })))
        .unwrap();
        let request = json!({
            "subject": {"kind": "user", "id": "u", "roles": [{"role": "member"}]},
            "permission": "project.view",
            "resource": {"path": [{"kind": "project", "id": "p1"}]}
        });
        assert!(engine.check(&ctx, request.clone()).unwrap());
        assert_eq!(engine.decide(&ctx, request).unwrap()["effect"], "allow");

        let out = engine
            .apply(
                json!({
                    "actor": {"kind": "user", "id": "admin"},
                    "current": ctx.grants(),
                    "mutation": {"add": {"id": "g2", "subject": {"kind": "any"}, "permission": "project.edit",
                                         "target": {"kind": "project"}, "effect": "allow"}},
                    "invariants": [{"kind": "catalog_conformance"}],
                    "audit": {"level": "forensic"}
                }),
                1_700_000_000_000,
            )
            .unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["grants"].as_array().unwrap().len(), 2);
        assert_eq!(out["audit"]["at"], 1_700_000_000_000u64);
        assert!(out["audit"]["hash"].is_string());
    }

    #[test]
    fn role_assignment_returns_the_new_subject() {
        let engine = EngineHandle::new(spec()).unwrap();
        let current = json!([{"id": "g", "subject": {"kind": "role", "id": "member"}, "permission": "project.view",
                              "target": {"kind": "project"}, "effect": "allow"}]);
        let input = |mutation: Value| {
            json!({
                "actor": {"kind": "user", "id": "admin"},
                "current": current,
                "mutation": mutation,
                "invariants": [{"kind": "catalog_conformance"}, {"kind": "no_self_management"}],
                "audit": {"level": "standard"}
            })
        };
        let out = engine
            .apply(
                input(json!({"assign_role": {"subject": {"kind": "user", "id": "bob"}, "role": {"role": "member"}}})),
                1,
            )
            .unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["subject"]["roles"], json!([{"role": "member"}]));
        assert_eq!(out["grants"].as_array().unwrap().len(), 1);
        assert_eq!(out["audit"]["action"], "role_assign");
        assert_eq!(out["audit"]["role"]["subject"], "bob");

        let out = engine
            .apply(
                input(json!({"revoke_role": {"subject": {"kind": "user", "id": "admin"}, "role": {"role": "member"}}})),
                1,
            )
            .unwrap();
        assert_eq!(out["ok"], false);
        assert!(out.get("subject").is_none());
        assert_eq!(out["audit"]["action"], "role_revoke");
        assert_eq!(out["audit"]["violations"], json!(["mutation"]));
    }

    #[test]
    fn errors_are_readable() {
        let err =
            EngineHandle::new(json!({"catalog": {"targetKinds": [], "permissions": [{"key": "Bad", "targets": []}]}}))
                .err()
                .unwrap();
        assert!(err.contains("chave inválida"));
        assert!(audit_estimate(json!("minimal"), 1e6).unwrap() > 1e8);
    }
}
