//! Synchronous host callbacks: JavaScript functions that the engine calls while it decides or
//! governs, shared by both targets.
//!
//! A target turns each JavaScript function into a [`HostFn`] (JSON in, JSON out); this module
//! builds the engine pieces on top of it: a `call` condition function, an override and a
//! governance invariant. The pattern is the one to reuse for any other host hook: wrap the
//! function in a [`HostFn`], register it in [`HostCallbacks`], and call it through [`invoke`] so
//! the re-entry guard covers it.
//!
//! What a callback receives is the JSON the same types take as input (a mutation looks like the
//! `mutation` of `apply`), so a suggestion it builds from it is accepted back as is.
//!
//! An error thrown by a callback never escapes: a condition resolves to an error (the grant does
//! not apply, a deny grant still does, and the trace carries the message), an override answers
//! `denied`, an invariant is violated with the message of the error.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use serde::Deserialize;
use serde_json::Value;
use strig::audit::{AuditSink, Auditor, FailMode, PendingQueue, RetryPolicy, mask_attributes};
use strig::{
    AuditError, AuditLevel, AuditRecord, ConditionError, ConditionRegistry, Context, Effect, Engine, EngineBuilder,
    Invariant, Mutation, Override, Proposal, Request, Violation,
};

use crate::{BindingError, BindingResult, parse};

/// A host function seen from the engine: one JSON argument, one JSON answer, or the message of
/// what it threw. It only runs on the thread of the host call that is deciding.
pub trait HostFn: Send + Sync {
    fn call(&self, arg: Value) -> Result<Value, String>;
}

impl<F> HostFn for F
where
    F: Fn(Value) -> Result<Value, String> + Send + Sync,
{
    fn call(&self, arg: Value) -> Result<Value, String> {
        self(arg)
    }
}

thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

struct Scope;

impl Scope {
    fn enter() -> Self {
        DEPTH.with(|d| d.set(d.get() + 1));
        Self
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// Calls the host function with the re-entry guard raised.
pub fn invoke(f: &dyn HostFn, arg: Value) -> Result<Value, String> {
    let _scope = Scope::enter();
    f.call(arg)
}

/// Refuses a call that comes from inside a callback. A callback runs in the middle of a decision,
/// while the engine and the context are borrowed by it; deciding again (unbounded recursion) or
/// changing the context (a mutable borrow of an object in use) is not safe, so the binding
/// answers `REENTRANT_CALL` instead.
pub fn forbid_reentry() -> BindingResult<()> {
    if DEPTH.with(Cell::get) == 0 {
        return Ok(());
    }
    Err(BindingError::new(
        "REENTRANT_CALL",
        "a callback cannot call the engine or change the context while it runs",
    ))
}

struct HostOverride {
    name: String,
    f: Arc<dyn HostFn>,
}

impl Override for HostOverride {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _: &Engine, ctx: &Context<'_>, request: &Request<'_>) -> Option<Effect> {
        let input = serde_json::json!({
            "subject": request.subject,
            "permission": request.permission,
            "resource": request.resource,
            "env": ctx.env,
            "now": ctx.now,
        });
        match invoke(self.f.as_ref(), input).and_then(|answer| outcome(&answer)) {
            Ok(effect) => effect,
            Err(_) => Some(Effect::Deny),
        }
    }
}

fn outcome(answer: &Value) -> Result<Option<Effect>, String> {
    match answer.as_str() {
        None if answer.is_null() => Ok(None),
        Some("abstained") => Ok(None),
        Some("allowed") => Ok(Some(Effect::Allow)),
        Some("denied") => Ok(Some(Effect::Deny)),
        _ => Err("an override returns 'allowed', 'denied' or 'abstained'".to_string()),
    }
}

/// An invariant that asks the host. Built per `apply`, from the registered function.
struct HostInvariant {
    name: String,
    f: Arc<dyn HostFn>,
    suggestion: Mutex<Option<Mutation>>,
}

impl HostInvariant {
    fn refuse(&self, message: String) -> Violation {
        Violation::new(self.name.clone(), message)
    }

    fn verdict(&self, answer: &Value) -> Result<Option<(String, Option<Mutation>)>, String> {
        let first = match answer {
            Value::Array(items) => items.first(),
            other => Some(other),
        };
        match first {
            None | Some(Value::Null) | Some(Value::Bool(true)) => Ok(None),
            Some(Value::String(message)) => Ok(Some((message.clone(), None))),
            Some(Value::Object(fields)) => {
                let message = fields
                    .get("message")
                    .and_then(Value::as_str)
                    .ok_or("a violation carries a text `message`")?
                    .to_string();
                let suggestion = match fields.get("suggestion") {
                    None | Some(Value::Null) => None,
                    Some(value) => Some(
                        parse::<Mutation>("suggestion", value.clone())
                            .map_err(|e| format!("invalid suggestion: {}", e.message))?,
                    ),
                };
                Ok(Some((message, suggestion)))
            }
            Some(_) => Err("an invariant returns nothing, a message, or `{ message, suggestion? }`".to_string()),
        }
    }
}

impl Invariant for HostInvariant {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self, _: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let input = serde_json::json!({
            "actor": proposal.actor,
            "mutation": proposal.mutation,
            "before": proposal.before,
            "after": proposal.after,
            "now": proposal.now,
        });
        let verdict = invoke(self.f.as_ref(), input)
            .and_then(|answer| self.verdict(&answer))
            .map_err(|message| self.refuse(message))?;
        match verdict {
            None => Ok(()),
            Some((message, suggestion)) => {
                if let Ok(mut slot) = self.suggestion.lock() {
                    *slot = suggestion;
                }
                Err(self.refuse(message))
            }
        }
    }

    fn remedy(&self, _: &Engine, _: &Proposal<'_>) -> Option<Mutation> {
        self.suggestion.lock().ok()?.take()
    }
}

struct OverrideEntry {
    name: String,
    except: Vec<String>,
    f: Arc<dyn HostFn>,
}

/// How the audit sink of the host is used: the failure mode of the records and the limits of the
/// retry queue that `open` mode feeds. The mode of one `apply` (`audit.failMode`) wins over the one
/// of the permission (`permissions`), which wins over `failMode`; the default is `closed`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditPolicy {
    #[serde(default)]
    pub fail_mode: FailMode,
    #[serde(default)]
    pub permissions: BTreeMap<String, FailMode>,
    pub capacity: Option<usize>,
    pub base_delay_ms: Option<u64>,
    pub max_delay_ms: Option<u64>,
}

/// A sink that calls the host function: it takes the record as JSON and throws to refuse it.
struct HostSink(Arc<dyn HostFn>);

impl AuditSink for HostSink {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let value = serde_json::to_value(record).map_err(|e| AuditError::Sink(e.to_string()))?;
        invoke(self.0.as_ref(), value).map(|_| ()).map_err(AuditError::Sink)
    }
}

/// The functions the host registered when it built the engine.
#[derive(Default)]
pub struct HostCallbacks {
    conditions: Vec<(String, Arc<dyn HostFn>)>,
    overrides: Vec<OverrideEntry>,
    invariants: BTreeMap<String, Arc<dyn HostFn>>,
    audit_sink: Option<Arc<dyn HostFn>>,
    audit_redact: Option<Arc<dyn HostFn>>,
    audit_on_drop: Option<Arc<dyn HostFn>>,
    audit_policy: AuditPolicy,
    queue: OnceLock<Arc<PendingQueue>>,
}

impl HostCallbacks {
    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
            && self.overrides.is_empty()
            && self.invariants.is_empty()
            && self.audit_sink.is_none()
            && self.audit_redact.is_none()
    }

    /// Where `apply` writes the audit records, instead of only returning them. The function takes the
    /// record (the JSON of `audit`) and throws to say the write failed, which applies the failure mode.
    pub fn audit_sink(&mut self, f: Arc<dyn HostFn>) {
        self.audit_sink = Some(f);
    }

    /// Masks each record before it is hashed and written: takes the record and returns it
    /// changed. A throw, or an answer that is not a record, refuses the change in any failure mode.
    pub fn audit_redact(&mut self, f: Arc<dyn HostFn>) {
        self.audit_redact = Some(f);
    }

    /// Called with the record that a full retry queue dropped.
    pub fn on_audit_drop(&mut self, f: Arc<dyn HostFn>) {
        self.audit_on_drop = Some(f);
    }

    pub fn set_audit_policy(&mut self, policy: AuditPolicy) {
        self.audit_policy = policy;
    }

    /// The retry queue, shared by every `apply` of the engine.
    fn queue(&self) -> &Arc<PendingQueue> {
        self.queue.get_or_init(|| {
            let defaults = RetryPolicy::default();
            let on_drop = self.audit_on_drop.clone().map(|f| {
                Arc::new(move |dropped: &strig::audit::DroppedRecord| {
                    if let Ok(value) = serde_json::to_value(&dropped.record) {
                        let _ = invoke(f.as_ref(), value);
                    }
                }) as strig::audit::DropHook
            });
            let mut policy = RetryPolicy::default()
                .with_capacity(self.audit_policy.capacity.unwrap_or(defaults.capacity))
                .with_base_delay_ms(self.audit_policy.base_delay_ms.unwrap_or(defaults.base_delay_ms))
                .with_max_delay_ms(self.audit_policy.max_delay_ms.unwrap_or(defaults.max_delay_ms));
            if let Some(hook) = on_drop {
                policy = policy.with_on_drop(hook);
            }
            Arc::new(PendingQueue::new(policy))
        })
    }

    fn sink(&self) -> Option<Arc<dyn AuditSink>> {
        self.audit_sink
            .clone()
            .map(|f| Arc::new(HostSink(f)) as Arc<dyn AuditSink>)
    }

    /// The auditor of one `apply`: the host's sink (or `fallback`, which discards), the policy, the
    /// shared queue and the redaction, the declarative one (`redact`) first and then the function.
    pub(crate) fn auditor(
        &self,
        level: AuditLevel,
        now: u64,
        redact: Option<&Redaction>,
        fallback: Arc<dyn AuditSink>,
    ) -> Auditor {
        let mut auditor = Auditor::new(level, self.sink().unwrap_or(fallback))
            .with_clock(move || now)
            .with_fail_mode(self.audit_policy.fail_mode)
            .with_queue(self.queue().clone());
        for (permission, mode) in &self.audit_policy.permissions {
            auditor = auditor.with_permission_fail_mode(permission.clone(), *mode);
        }
        let masker = redact.map(|r| mask_attributes(r.keys.clone(), r.mask.clone()));
        let hook = self.audit_redact.clone();
        if masker.is_some() || hook.is_some() {
            auditor = auditor.with_redactor(Arc::new(move |record: &mut AuditRecord| {
                if let Some(masker) = &masker {
                    masker(record)?;
                }
                if let Some(f) = &hook {
                    let value = serde_json::to_value(&*record).map_err(|e| e.to_string())?;
                    let answer = invoke(f.as_ref(), value)?;
                    *record = serde_json::from_value(crate::integral(answer))
                        .map_err(|e| format!("the redaction must return the record: {e}"))?;
                }
                Ok(())
            }));
        }
        auditor
    }

    /// Tries the waiting records now and answers the counters of the queue.
    pub(crate) fn flush_audit(&self, now: u64) -> Value {
        if let Some(sink) = self.sink() {
            self.queue().flush(sink.as_ref(), now, true);
        }
        serde_json::to_value(self.queue().stats()).unwrap_or(Value::Null)
    }

    pub(crate) fn audit_stats(&self) -> Value {
        serde_json::to_value(self.queue().stats()).unwrap_or(Value::Null)
    }

    /// Function of the `call` condition, by name. The function gets the list of resolved operands.
    pub fn condition(&mut self, name: impl Into<String>, f: Arc<dyn HostFn>) {
        self.conditions.push((name.into(), f));
    }

    /// Override that runs after the ones in the spec, in registration order.
    pub fn override_rule(&mut self, name: impl Into<String>, except: Vec<String>, f: Arc<dyn HostFn>) {
        self.overrides.push(OverrideEntry {
            name: name.into(),
            except,
            f,
        });
    }

    /// Invariant that `apply` runs when the input lists `{ kind: 'custom', name }`.
    pub fn invariant(&mut self, name: impl Into<String>, f: Arc<dyn HostFn>) {
        self.invariants.insert(name.into(), f);
    }

    pub(crate) fn extend(&self, builder: EngineBuilder) -> EngineBuilder {
        let mut registry = ConditionRegistry::new();
        for (name, f) in &self.conditions {
            let f = f.clone();
            registry = registry.register(name.clone(), move |args| {
                let args = serde_json::to_value(args).map_err(|e| ConditionError::Function(e.to_string()))?;
                let answer =
                    invoke(f.as_ref(), args).map_err(|m| ConditionError::Function(format!("callback: {m}")))?;
                answer
                    .as_bool()
                    .ok_or_else(|| ConditionError::Function("a condition function returns a boolean".to_string()))
            });
        }
        let mut builder = builder;
        if !self.conditions.is_empty() {
            builder = builder.conditions(registry);
        }
        for entry in &self.overrides {
            let rule = HostOverride {
                name: entry.name.clone(),
                f: entry.f.clone(),
            };
            builder = builder.override_except(rule, entry.except.clone());
        }
        builder
    }

    pub(crate) fn invariant_named(&self, name: &str) -> BindingResult<impl Invariant + 'static> {
        let f = self
            .invariants
            .get(name)
            .ok_or_else(|| BindingError::new("UNKNOWN_INVARIANT", format!("invariant not registered: {name}")))?;
        Ok(HostInvariant {
            name: name.to_string(),
            f: f.clone(),
            suggestion: Mutex::new(None),
        })
    }
}

/// The `audit.redact` of an `apply`: attributes whose value is replaced by `mask` before the
/// record is hashed and written.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Redaction {
    pub keys: Vec<String>,
    #[serde(default = "Redaction::default_mask")]
    pub mask: String,
}

impl Redaction {
    fn default_mask() -> String {
        "[redacted]".to_string()
    }
}

/// Takes the `{ kind: 'custom', name }` entries out of `input.invariants` (the rest is the
/// declarative list) and returns their names, in order.
pub(crate) fn take_custom(input: &mut Value) -> BindingResult<Vec<String>> {
    let Some(Value::Array(list)) = input.get_mut("invariants") else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    let mut declarative = Vec::new();
    for item in std::mem::take(list) {
        if item.get("kind").and_then(Value::as_str) != Some("custom") {
            declarative.push(item);
            continue;
        }
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| BindingError::invalid_input("invariants", "a custom invariant has a text `name`"))?;
        names.push(name.to_string());
    }
    *list = declarative;
    Ok(names)
}
