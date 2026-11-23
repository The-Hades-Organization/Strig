//! Bindings JavaScript da Themis.
//!
//! O núcleo ([`EngineHandle`], [`ContextData`]) recebe e devolve `serde_json::Value` e é o
//! mesmo nos dois alvos. `napi` gera o módulo nativo para Node e Bun; `wasm` gera o
//! WebAssembly para o navegador. O pacote npm em `js/` escolhe o alvo em tempo de execução.

mod error;
mod exclusive;
mod query_json;

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};
use themis::audit::{AuditLevel, Auditor, MemoryAuditLog};
use themis::{
    Attributes, CapabilitySet, Context, Engine, EngineSpec, Governance, Grant, InMemorySubjects, InMemoryTuples,
    InvariantSpec, Mutation, PathLayout, QueryContext, QueryLimits, Request, Resource, RoleTemplate, Subject, Tuple,
};

pub use error::{BindingError, BindingResult};
pub use exclusive::ExclusiveHandle;
use query_json::{expr_json, parse_subject_ref, residual_json, shape_json, subject_ref_json, via_json};

#[cfg(feature = "napi")]
mod napi_binding;
#[cfg(feature = "wasm")]
mod wasm_binding;

fn parse<T: for<'de> Deserialize<'de>>(what: &str, value: Value) -> BindingResult<T> {
    serde_json::from_value(value).map_err(|e| BindingError::invalid_input(what, e))
}

fn to_value<T: serde::Serialize>(value: &T) -> Value {
    // Os tipos da Themis só têm chaves de texto e números finitos: a serialização não falha.
    serde_json::to_value(value).expect("tipos da Themis sempre serializam")
}

/// Largest integer a JavaScript number holds exactly.
const MAX_SAFE_INT: f64 = 9_007_199_254_740_991.0;

/// Milissegundos desde a época Unix, vindos de um número JavaScript: inteiro, finito e não negativo.
pub fn millis(what: &str, value: f64) -> BindingResult<u64> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > MAX_SAFE_INT {
        return Err(BindingError::invalid_input(
            what,
            "esperado um inteiro não negativo em milissegundos",
        ));
    }
    // Inteiro, finito e dentro de 2^53: a conversão não perde valor.
    Ok(value as u64)
}

fn millis_value(what: &str, value: &Value) -> BindingResult<u64> {
    let number = value
        .as_f64()
        .ok_or_else(|| BindingError::invalid_input(what, "esperado um número"))?;
    millis(what, number)
}

fn count_value(what: &str, value: &Value) -> BindingResult<usize> {
    usize::try_from(millis_value(what, value)?).map_err(|e| BindingError::invalid_input(what, e))
}

/// Grants, tuplas, ambiente e instante de uma decisão, mantidos do lado Rust para não converter
/// a cada chamada. Sem `now`, o motor falha fechado: um allow com janela é ignorado e um deny com
/// janela vale.
#[derive(Default)]
pub struct ContextData {
    grants: Vec<Grant>,
    tuples: InMemoryTuples,
    env: Attributes,
    with_tuples: bool,
    now: Option<u64>,
    limits: Option<QueryLimits>,
}

impl ContextData {
    pub fn new(init: Option<Value>) -> BindingResult<Self> {
        let mut data = Self::default();
        let Some(init) = init else {
            return Ok(data);
        };
        let Value::Object(init) = init else {
            if init.is_null() {
                return Ok(data);
            }
            return Err(BindingError::invalid_input("context", "esperado um objeto"));
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
        if let Some(now) = init.get("now") {
            data.set_now(now.clone())?;
        }
        if let Some(limits) = init.get("limits") {
            data.set_limits(limits.clone())?;
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

    /// Instante das decisões e das consultas, em milissegundos UTC. `null` o remove.
    pub fn set_now(&mut self, now: Value) -> BindingResult<()> {
        self.now = if now.is_null() {
            None
        } else {
            Some(millis_value("now", &now)?)
        };
        Ok(())
    }

    pub fn now(&self) -> Option<u64> {
        self.now
    }

    /// Tetos das consultas reversas: `{ maxParties?, maxDecisions? }`. O que falta fica no padrão;
    /// `null` volta tudo ao padrão.
    pub fn set_limits(&mut self, limits: Value) -> BindingResult<()> {
        if limits.is_null() {
            self.limits = None;
            return Ok(());
        }
        let Value::Object(map) = limits else {
            return Err(BindingError::invalid_input("limits", "esperado um objeto"));
        };
        let mut out = QueryLimits::default();
        if let Some(parties) = map.get("maxParties") {
            out = out.with_max_parties(count_value("limits.maxParties", parties)?);
        }
        if let Some(decisions) = map.get("maxDecisions") {
            out = out.with_max_decisions(count_value("limits.maxDecisions", decisions)?);
        }
        self.limits = Some(out);
        Ok(())
    }

    /// Troca os grants pelos de um `CapabilitySet` recebido do servidor.
    pub fn load_capabilities(&mut self, set: Value) -> BindingResult<Value> {
        let set: CapabilitySet = parse("capabilities", set)?;
        self.grants = set.grants;
        Ok(to_value(&set.subject))
    }

    pub(crate) fn context(&self) -> Context<'_> {
        let mut ctx = Context::new(&self.grants).with_env(&self.env);
        if let Some(now) = self.now {
            ctx = ctx.at(now);
        }
        if self.with_tuples {
            ctx = ctx.with_tuples(&self.tuples);
        }
        ctx
    }

    fn query_context(&self) -> QueryContext<'_> {
        let mut ctx = QueryContext::new(&self.grants).with_env(&self.env);
        if let Some(now) = self.now {
            ctx = ctx.at(now);
        }
        if let Some(limits) = self.limits {
            ctx = ctx.with_limits(limits);
        }
        if self.with_tuples {
            ctx = ctx.with_tuples(&self.tuples);
        }
        ctx
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
    #[serde(default)]
    now: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TemplateInput {
    template: RoleTemplate,
    subject: themis::SubjectMatcher,
    #[serde(default)]
    scope: Option<themis::Anchor>,
    id_prefix: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyTemplateInput {
    actor: Subject,
    current: Vec<Grant>,
    #[serde(flatten)]
    template: TemplateInput,
    #[serde(default)]
    invariants: Vec<InvariantSpec>,
    #[serde(default)]
    tuples: Option<Vec<Tuple>>,
    #[serde(default)]
    audit: Option<AuditInput>,
    #[serde(default)]
    meta: Attributes,
    #[serde(default)]
    now: Option<Value>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ListOptions {
    /// Passos do caminho, do `kind` listado ao mais amplo (`["document", "project", "org"]`).
    #[serde(default)]
    layout: Vec<String>,
    /// Recursos a avaliar contra o filtro, para devolver os ids permitidos.
    #[serde(default)]
    resources: Option<Vec<Resource>>,
}

pub struct EngineHandle {
    engine: Engine,
}

/// Como uma mudança é aplicada: com as invariantes, a auditoria e o instante.
struct Governed<'a> {
    invariants: &'a [InvariantSpec],
    audit: Option<&'a AuditInput>,
    tuples: Option<InMemoryTuples>,
    meta: &'a Attributes,
    now: u64,
}

impl Governed<'_> {
    fn governance(&self, log: Option<&Arc<MemoryAuditLog>>) -> Governance {
        let governance: Governance = self.invariants.iter().collect();
        let (Some(audit), Some(log)) = (self.audit, log) else {
            return governance;
        };
        let now = self.now;
        let mut auditor = Auditor::new(audit.level, log.clone()).with_clock(move || now);
        if let Some(prev) = &audit.prev_hash {
            auditor = auditor.resume_chain(prev.clone());
        }
        governance.audited(Arc::new(auditor))
    }

    fn store(&self) -> Option<&dyn themis::TupleStore> {
        self.tuples.as_ref().map(|s| s as &dyn themis::TupleStore)
    }
}

impl EngineHandle {
    pub fn new(spec: Value) -> BindingResult<Self> {
        let spec: EngineSpec = parse("spec", spec)?;
        let engine = spec
            .build()
            .map_err(|e| BindingError::new("INVALID_SPEC", e.to_string()))?;
        Ok(Self { engine })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
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
        self.engine
            .validate_grant(&grant)
            .map_err(|e| BindingError::new("INVALID_GRANT", e.to_string()))
    }

    pub fn catalog(&self) -> Value {
        to_value(&self.engine.catalog().export())
    }

    /// O alcance de `subject` com `permission` sobre os recursos de `kind`, sem enumerar a
    /// tabela: `{ kind, permission, exact, shape, expr, residual, warnings, ids }`. `expr` é a
    /// forma estrutural sobre `options.layout`; `ids` só vem com `options.resources`, e já traz
    /// os recursos que só o motor decide, resolvidos por `check`. O que só o recurso decide fica em
    /// `residual` e nunca conta como permissão.
    pub fn list(
        &self,
        ctx: &ContextData,
        subject: Value,
        permission: &str,
        kind: &str,
        options: Option<Value>,
    ) -> BindingResult<Value> {
        let subject: Subject = parse("subject", subject)?;
        let options: ListOptions = match options {
            Some(v) if !v.is_null() => parse("options", v)?,
            _ => ListOptions::default(),
        };
        let mut layout = PathLayout::new(kind);
        for step in options.layout.iter().filter(|step| step.as_str() != kind) {
            layout = layout.within(step.as_str());
        }
        let query = ctx.query_context();
        let filter = self.engine.list(&query, &subject, permission, kind);
        let ids = options
            .resources
            .as_ref()
            .map(|resources| filter.resolve_with(&self.engine, &query.context(), resources));
        Ok(json!({
            "kind": filter.kind(),
            "permission": filter.permission(),
            "exact": filter.is_exact(&layout),
            "shape": shape_json(&filter.shape(&layout)),
            "expr": expr_json(&filter.expr(&layout)),
            "residual": filter.residual_for(&layout).iter().map(residual_json).collect::<Vec<_>>(),
            "warnings": filter.warnings(),
            "ids": ids,
        }))
    }

    /// Partes nomeadas por um grant allow da permissão, em qualquer lugar.
    pub fn who_can(&self, ctx: &ContextData, permission: &str) -> Value {
        let parties = self.engine.who_can(&ctx.query_context(), permission);
        Value::Array(parties.iter().map(subject_ref_json).collect())
    }

    /// Quem tem a permissão sobre o recurso, com o caminho de cada parte.
    ///
    /// # Errors
    /// `QUERY_LIMIT_EXCEEDED` e `RELATION_DEPTH_EXCEEDED`.
    pub fn who_can_on(&self, ctx: &ContextData, permission: &str, resource: Value) -> BindingResult<Value> {
        let resource: Resource = parse("resource", resource)?;
        let who = self.engine.who_can_on(&ctx.query_context(), permission, &resource)?;
        let entries: Vec<Value> = who
            .entries
            .iter()
            .map(|e| json!({"subject": subject_ref_json(&e.subject), "via": via_json(&e.via)}))
            .collect();
        let except: Vec<Value> = who
            .except
            .iter()
            .map(|e| json!({"allowed": subject_ref_json(&e.allowed), "with": subject_ref_json(&e.with)}))
            .collect();
        Ok(json!({"permission": who.permission, "resource": who.resource, "entries": entries, "except": except}))
    }

    /// O que cada parte pode fazer no recurso.
    ///
    /// # Errors
    /// `QUERY_LIMIT_EXCEEDED` e `RELATION_DEPTH_EXCEEDED`.
    pub fn access_of(&self, ctx: &ContextData, resource: Value) -> BindingResult<Value> {
        let resource: Resource = parse("resource", resource)?;
        let parties = self.engine.access_of(&ctx.query_context(), &resource)?;
        Ok(Value::Array(
            parties
                .iter()
                .map(|p| json!({"subject": subject_ref_json(&p.subject), "permissions": p.permissions}))
                .collect(),
        ))
    }

    /// A decisão para um sujeito nomeado por referência, com o caminho que decidiu. `subjects`
    /// são os sujeitos que o resolvedor conhece (`user` e `object` por id); uma referência fora
    /// dele falha com `UNKNOWN_SUBJECT`, nunca responde como um sujeito inventado.
    pub fn check_for(
        &self,
        ctx: &ContextData,
        subject_ref: Value,
        permission: &str,
        resource: Value,
        subjects: Value,
    ) -> BindingResult<Value> {
        let reference = parse_subject_ref(subject_ref)?;
        let resource: Resource = parse("resource", resource)?;
        let subjects: Vec<Subject> = parse("subjects", subjects)?;
        let resolver = subjects
            .into_iter()
            .fold(InMemorySubjects::new(), |known, subject| known.with(subject));
        let answer = self
            .engine
            .check_for(&ctx.query_context(), &resolver, &reference, permission, &resource)?;
        Ok(json!({
            "subject": subject_ref_json(&answer.subject),
            "allowed": answer.is_allowed(),
            "decision": answer.decision,
            "via": via_json(&answer.via),
            "explanation": answer.explanation,
        }))
    }

    /// Aplica uma mudança de grant ou de papel pelos invariantes, no instante `input.now` (ou em
    /// `clock_ms`, o relógio do alvo). Devolve `{ ok, grants?, subject?, violations?, audit? }`;
    /// `subject` é o sujeito com o papel aplicado, numa mudança de papel aceita, e `audit` é o
    /// registro a gravar quando a entrada pede auditoria. As janelas de validade do ator contam
    /// nesse instante.
    pub fn apply(&self, input: Value, clock_ms: u64) -> BindingResult<Value> {
        let input: ApplyInput = parse("apply", input)?;
        let now = match &input.now {
            Some(v) if !v.is_null() => millis_value("now", v)?,
            _ => clock_ms,
        };
        let governed = Governed {
            invariants: &input.invariants,
            audit: input.audit.as_ref(),
            tuples: input.tuples.map(|t| t.into_iter().collect()),
            meta: &input.meta,
            now,
        };
        let log = Arc::new(MemoryAuditLog::new());
        let governance = governed.governance(Some(&log));
        let result = governance.at(now).apply_with(
            &self.engine,
            &input.actor,
            &input.current,
            &input.mutation,
            governed.store(),
            governed.meta,
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

    /// Materializa um template em grants comuns, sem vínculo com ele: o resultado é só uma cópia
    /// (`{ template, templateVersion, mutations, meta }`) e mudar o template depois não muda o que
    /// já foi aplicado.
    pub fn materialize(&self, input: Value) -> BindingResult<Value> {
        let input: TemplateInput = parse("template", input)?;
        let materialized = input
            .template
            .materialize(input.subject, input.scope, &input.id_prefix);
        Ok(to_value(&materialized))
    }

    /// Materializa o template e aplica o lote pela governança, na ordem das dependências
    /// (`depends_on`). O lote inteiro é simulado antes de gravar qualquer registro de auditoria:
    /// numa recusa, `ok` é `false`, só a recusa vai à trilha e nada deve ser gravado. Devolve
    /// `{ ok, grants?, violations?, audits }`.
    pub fn apply_template(&self, input: Value, clock_ms: u64) -> BindingResult<Value> {
        let input: ApplyTemplateInput = parse("template", input)?;
        let now = match &input.now {
            Some(v) if !v.is_null() => millis_value("now", v)?,
            _ => clock_ms,
        };
        let materialized = input.template.template.materialize(
            input.template.subject,
            input.template.scope,
            &input.template.id_prefix,
        );
        let mut meta = materialized.meta.clone();
        meta.extend(input.meta.clone());
        let governed = Governed {
            invariants: &input.invariants,
            audit: input.audit.as_ref(),
            tuples: input.tuples.map(|t| t.into_iter().collect()),
            meta: &meta,
            now,
        };
        let ordered = materialized.ordered(&self.engine);
        let log = Arc::new(MemoryAuditLog::new());
        let audited = governed.governance(Some(&log));

        // Simulação sem auditoria: a trilha nunca diz `applied` de um lote que será descartado.
        let silent = governed.governance(None);
        let mut grants = input.current.clone();
        for mutation in &ordered {
            match silent.at(now).apply_with(
                &self.engine,
                &input.actor,
                &grants,
                mutation,
                governed.store(),
                governed.meta,
            ) {
                Ok(next) => grants = next,
                Err(violations) => {
                    // Registra só a recusa, no estado em que o lote chegou nela.
                    let refused = audited.at(now).apply_with(
                        &self.engine,
                        &input.actor,
                        &grants,
                        mutation,
                        governed.store(),
                        governed.meta,
                    );
                    let violations = refused.err().unwrap_or(violations);
                    let audits: Vec<Value> = log.drain().iter().map(to_value).collect();
                    return Ok(json!({"ok": false, "violations": violations, "audits": audits}));
                }
            }
        }
        let mut grants = input.current;
        for mutation in &ordered {
            match audited.at(now).apply_with(
                &self.engine,
                &input.actor,
                &grants,
                mutation,
                governed.store(),
                governed.meta,
            ) {
                Ok(next) => grants = next,
                Err(violations) => {
                    let audits: Vec<Value> = log.drain().iter().map(to_value).collect();
                    return Ok(json!({"ok": false, "violations": violations, "audits": audits}));
                }
            }
        }
        let audits: Vec<Value> = log.drain().iter().map(to_value).collect();
        Ok(json!({"ok": true, "grants": grants, "audits": audits}))
    }
}

/// Bytes estimados para `records` registros de auditoria no nível dado.
pub fn audit_estimate(level: Value, records: f64) -> BindingResult<f64> {
    let level: AuditLevel = parse("level", level)?;
    let records = millis("records", records.max(0.0).floor())?;
    // O estimado passa de 2^53 só com registros absurdos: a perda de precisão é só de arredondamento.
    Ok(level.estimate_bytes(records) as f64)
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
        assert_eq!(err.code, "INVALID_SPEC");
        assert!(err.message.contains("chave inválida"));
        assert!(audit_estimate(json!("minimal"), 1e6).unwrap() > 1e8);
    }
}
