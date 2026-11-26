//! Full trace of a decision: why each grant got in or stayed out, what each override answered
//! and how the strategy chose. [`crate::Engine::explain`] returns the same [`Decision`] as
//! [`crate::Engine::decide`], plus the path that led to it.

use serde::{Deserialize, Serialize};

use crate::attr::Value;
use crate::condition::{Condition, ConditionRegistry, EvalContext, Operand, clock_label};
use crate::decision::Decision;
use crate::grant::{Effect, Grant};
use crate::resource::{Anchor, Resource};
use crate::subject::Subject;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Explanation {
    pub subject: Subject,
    pub permission: String,
    pub resource: Resource,
    /// The requested permission and the ones that grant it. Empty if the permission is not in the catalog.
    pub effective: Vec<String>,
    /// Steps of the resource with the implicit `global` at the end. The position is the `rank`.
    pub path: Vec<Anchor>,
    /// Roles of the subject that hold for the resource, including inherited ones.
    pub roles: Vec<String>,
    pub overrides: Vec<OverrideStep>,
    /// All the grants the source delivered, in its order.
    pub grants: Vec<GrantTrace>,
    pub strategy: String,
    /// The prerequisites (`depends_on`, transitive) consulted because the permission was allowed,
    /// with their own outcome. Empty when the permission has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prerequisites: Vec<PrerequisiteStep>,
    pub decision: Decision,
}

/// A prerequisite consulted in a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrerequisiteStep {
    pub permission: String,
    /// The prerequisite is allowed on the same resource.
    pub allowed: bool,
}

impl Explanation {
    /// The grant that decided, if a grant did. `None` when the reason is an override or a missing
    /// prerequisite: the grants listed are still the candidates, but none of them decided.
    pub fn decisive(&self) -> Option<&GrantTrace> {
        match &self.decision.reason {
            crate::Reason::Grant { grant_id, .. } => self
                .grants
                .iter()
                .find(|g| &g.grant.id == grant_id && g.verdict.is_candidate()),
            _ => None,
        }
    }

    pub fn candidates(&self) -> impl Iterator<Item = &GrantTrace> {
        self.grants.iter().filter(|g| g.verdict.is_candidate())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideStep {
    pub name: String,
    pub outcome: OverrideOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideOutcome {
    /// The permission is in the override's exceptions; it was not even consulted.
    Excepted,
    /// Consulted, did not rule.
    Abstained,
    Allowed,
    Denied,
}

impl From<Option<Effect>> for OverrideOutcome {
    fn from(effect: Option<Effect>) -> Self {
        match effect {
            None => OverrideOutcome::Abstained,
            Some(Effect::Allow) => OverrideOutcome::Allowed,
            Some(Effect::Deny) => OverrideOutcome::Denied,
        }
    }
}

/// The fate of a grant during collection, in the order the engine checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    /// Became a candidate.
    Candidate,
    /// `deny` that became a candidate even though the subject or the condition could not be evaluated.
    CandidateFailSafe {
        problem: String,
    },
    /// The grant's permission is not the requested one and does not grant it.
    PermissionUnrelated,
    /// The grant is outside its validity window at the decision instant, or has a window and the
    /// context carries no instant (an `allow` is then ignored; a `deny` is never discarded for it).
    OutsideWindow,
    /// The grant's scope is not in the resource path.
    OutOfScope,
    /// The grant's target matches no step of the path.
    TargetNotOnPath,
    SubjectMismatch,
    /// `allow` discarded because the subject could not be evaluated (ReBAC without tuples, depth).
    SubjectUnresolved {
        problem: String,
    },
    ConditionFalse,
    /// `allow` discarded because the condition could not be evaluated.
    ConditionUnresolved {
        problem: String,
    },
    /// The grant, or the requested permission, is marked `override_only`: grants are ignored.
    OverrideOnly,
    /// An override decided before collection.
    NotReached,
}

impl Verdict {
    pub fn is_candidate(&self) -> bool {
        matches!(self, Verdict::Candidate | Verdict::CandidateFailSafe { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantTrace {
    pub grant: Grant,
    pub verdict: Verdict,
    /// Position of the step matched by the target (0 = most specific).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<Anchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConditionTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum TraceResult {
    True,
    False,
    Error(String),
    /// Not evaluated: an earlier sibling already decided the `all`/`any`.
    Skipped,
}

/// Evaluation of a condition, node by node, with the resolved values in the label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionTrace {
    pub label: String,
    pub result: TraceResult,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<ConditionTrace>,
}

fn show_value(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| format!("{value:?}"))
}

fn show_operand(ctx: &EvalContext<'_>, operand: &Operand) -> String {
    match operand {
        Operand::Lit(value) => show_value(value),
        Operand::Attr { attr } => match ctx.resolve(attr) {
            Ok(Some(value)) => format!("{attr} ({})", show_value(&value)),
            Ok(None) => format!("{attr} (ausente)"),
            Err(_) => format!("{attr} (caminho inválido)"),
        },
    }
}

fn result_of(outcome: &Result<bool, crate::ConditionError>) -> TraceResult {
    match outcome {
        Ok(true) => TraceResult::True,
        Ok(false) => TraceResult::False,
        Err(error) => TraceResult::Error(error.to_string()),
    }
}

fn skipped(
    condition: &Condition,
    ctx: &EvalContext<'_>,
    registry: &ConditionRegistry,
    now: Option<u64>,
) -> ConditionTrace {
    let mut node = trace_condition_at(condition, ctx, registry, now);
    mark_skipped(&mut node);
    node
}

fn mark_skipped(node: &mut ConditionTrace) {
    node.result = TraceResult::Skipped;
    node.children.iter_mut().for_each(mark_skipped);
}

/// Evaluates `condition` the way the engine does (with short-circuiting) and returns the tree.
/// Without a decision instant the time conditions trace as errors; see [`trace_condition_at`].
pub fn trace_condition(condition: &Condition, ctx: &EvalContext<'_>, registry: &ConditionRegistry) -> ConditionTrace {
    trace_condition_at(condition, ctx, registry, None)
}

/// [`trace_condition`] at the decision instant `now`, in milliseconds since the Unix epoch.
pub fn trace_condition_at(
    condition: &Condition,
    ctx: &EvalContext<'_>,
    registry: &ConditionRegistry,
    now: Option<u64>,
) -> ConditionTrace {
    let binary = |op: &str, left: &Operand, right: &Operand| {
        format!("{} {op} {}", show_operand(ctx, left), show_operand(ctx, right))
    };
    let leaf = |label: String| ConditionTrace {
        label,
        result: result_of(&condition.evaluate_at(ctx, registry, now)),
        children: Vec::new(),
    };
    match condition {
        Condition::Eq { left, right } => leaf(binary("=", left, right)),
        Condition::Ne { left, right } => leaf(binary("≠", left, right)),
        Condition::Lt { left, right } => leaf(binary("<", left, right)),
        Condition::Le { left, right } => leaf(binary("≤", left, right)),
        Condition::Gt { left, right } => leaf(binary(">", left, right)),
        Condition::Ge { left, right } => leaf(binary("≥", left, right)),
        Condition::In { item, set } => leaf(binary("∈", item, set)),
        Condition::StartsWith { left, right } => leaf(binary("começa com", left, right)),
        Condition::EndsWith { left, right } => leaf(binary("termina com", left, right)),
        Condition::Contains { left, right } => leaf(binary("contém", left, right)),
        Condition::AnyIn { left, right } => leaf(binary("tem algum em", left, right)),
        Condition::AllIn { left, right } => leaf(binary("tem todos em", left, right)),
        Condition::IpIn { item, set } => leaf(binary("IP em", item, set)),
        Condition::TimeBetween { from, until, tz } => leaf(format!(
            "hora {} em [{from}, {until})",
            clock_label(now, tz.as_deref(), false)
        )),
        Condition::WeekdayIn { days, tz } => leaf(format!(
            "dia {} em {}",
            clock_label(now, tz.as_deref(), true),
            days.join(", ")
        )),
        Condition::Exists { attr } => leaf(format!("existe {}", show_operand(ctx, &Operand::attr(attr.clone())))),
        Condition::Call { func, args } => {
            let args: Vec<String> = args.iter().map(|a| show_operand(ctx, a)).collect();
            leaf(format!("{func}({})", args.join(", ")))
        }
        Condition::Not { cond } => ConditionTrace {
            label: "não".into(),
            result: result_of(&condition.evaluate_at(ctx, registry, now)),
            children: vec![trace_condition_at(cond, ctx, registry, now)],
        },
        Condition::All { of } | Condition::Any { of } => {
            let stop_on = matches!(condition, Condition::Any { .. });
            let mut children = Vec::with_capacity(of.len());
            let mut done = false;
            for child in of {
                if done {
                    children.push(skipped(child, ctx, registry, now));
                    continue;
                }
                let node = trace_condition_at(child, ctx, registry, now);
                done = match node.result {
                    TraceResult::True => stop_on,
                    TraceResult::False => !stop_on,
                    _ => true,
                };
                children.push(node);
            }
            ConditionTrace {
                label: if stop_on { "qualquer um" } else { "todos" }.into(),
                result: result_of(&condition.evaluate_at(ctx, registry, now)),
                children,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::Attributes;

    #[test]
    fn condition_tree_matches_evaluation_and_short_circuits() {
        let subject = Subject::user("u").with_attr("plan", "free");
        let resource = Resource::new("doc", "d");
        let env = Attributes::new();
        let ctx = EvalContext {
            subject: &subject,
            resource: &resource,
            env: &env,
        };
        let cond = Condition::all([
            Condition::eq(Operand::attr("subject.plan"), Operand::lit("pro")),
            Condition::exists("subject.missing"),
        ]);
        let registry = ConditionRegistry::new();
        let tree = trace_condition(&cond, &ctx, &registry);
        assert_eq!(tree.result, TraceResult::False);
        assert_eq!(tree.children[0].label, r#"subject.plan ("free") = "pro""#);
        assert_eq!(tree.children[0].result, TraceResult::False);
        assert_eq!(tree.children[1].result, TraceResult::Skipped);
    }
}
