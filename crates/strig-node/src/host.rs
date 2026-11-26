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
use std::sync::{Arc, Mutex};

use serde_json::Value;
use strig::{
    ConditionError, ConditionRegistry, Context, Effect, Engine, EngineBuilder, Invariant, Mutation, Override, Proposal,
    Request, Violation,
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

/// The functions the host registered when it built the engine.
#[derive(Default)]
pub struct HostCallbacks {
    conditions: Vec<(String, Arc<dyn HostFn>)>,
    overrides: Vec<OverrideEntry>,
    invariants: BTreeMap<String, Arc<dyn HostFn>>,
}

impl HostCallbacks {
    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty() && self.overrides.is_empty() && self.invariants.is_empty()
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
