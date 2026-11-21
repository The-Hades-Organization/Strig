//! Rastro completo de uma decisão: por que cada grant entrou ou ficou de fora, o que cada
//! override respondeu e como a estratégia escolheu. [`crate::Engine::explain`] devolve a mesma
//! [`Decision`] de [`crate::Engine::decide`], mais o caminho até ela.

use serde::{Deserialize, Serialize};

use crate::attr::Value;
use crate::condition::{Condition, ConditionRegistry, EvalContext, Operand};
use crate::decision::Decision;
use crate::grant::{Effect, Grant};
use crate::resource::{Anchor, Resource};
use crate::subject::Subject;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Explanation {
    pub subject: Subject,
    pub permission: String,
    pub resource: Resource,
    /// A permissão pedida e as que a concedem. Vazio se a permissão não existe no catálogo.
    pub effective: Vec<String>,
    /// Degraus do recurso com o `global` implícito no fim. A posição é o `rank`.
    pub path: Vec<Anchor>,
    /// Papéis do sujeito que valem para o recurso, já com os herdados.
    pub roles: Vec<String>,
    pub overrides: Vec<OverrideStep>,
    /// Todos os grants que a fonte entregou, na ordem dela.
    pub grants: Vec<GrantTrace>,
    pub strategy: String,
    pub decision: Decision,
}

impl Explanation {
    /// O grant que decidiu, se foi um grant.
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
    /// A permissão está nas exceções do override; ele nem foi consultado.
    Excepted,
    /// Consultado, não se pronunciou.
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

/// O destino de um grant na coleta, na ordem em que o motor confere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    /// Entrou como candidato.
    Candidate,
    /// `deny` que entrou apesar de o sujeito ou a condição não poderem ser avaliados.
    CandidateFailSafe {
        problem: String,
    },
    /// A permissão do grant não é a pedida nem a concede.
    PermissionUnrelated,
    /// O escopo do grant não está no caminho do recurso.
    OutOfScope,
    /// O alvo do grant não casa nenhum degrau do caminho.
    TargetNotOnPath,
    SubjectMismatch,
    /// `allow` descartado porque o sujeito não pôde ser avaliado (ReBAC sem tuplas, profundidade).
    SubjectUnresolved {
        problem: String,
    },
    ConditionFalse,
    /// `allow` descartado porque a condição não pôde ser avaliada.
    ConditionUnresolved {
        problem: String,
    },
    /// Um override decidiu antes da coleta.
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
    /// Posição do degrau casado pelo alvo (0 = mais específico).
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
    /// Não avaliado: um irmão anterior já decidiu o `all`/`any`.
    Skipped,
}

/// Avaliação de uma condição, nó a nó, com os valores resolvidos no rótulo.
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

fn skipped(condition: &Condition, ctx: &EvalContext<'_>, registry: &ConditionRegistry) -> ConditionTrace {
    let mut node = trace_condition(condition, ctx, registry);
    mark_skipped(&mut node);
    node
}

fn mark_skipped(node: &mut ConditionTrace) {
    node.result = TraceResult::Skipped;
    node.children.iter_mut().for_each(mark_skipped);
}

/// Avalia `condition` como o motor avalia (com curto-circuito) e devolve a árvore.
pub fn trace_condition(condition: &Condition, ctx: &EvalContext<'_>, registry: &ConditionRegistry) -> ConditionTrace {
    let binary = |op: &str, left: &Operand, right: &Operand| {
        format!("{} {op} {}", show_operand(ctx, left), show_operand(ctx, right))
    };
    let leaf = |label: String| ConditionTrace {
        label,
        result: result_of(&condition.evaluate(ctx, registry)),
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
        Condition::Exists { attr } => leaf(format!("existe {}", show_operand(ctx, &Operand::attr(attr.clone())))),
        Condition::Call { func, args } => {
            let args: Vec<String> = args.iter().map(|a| show_operand(ctx, a)).collect();
            leaf(format!("{func}({})", args.join(", ")))
        }
        Condition::Not { cond } => ConditionTrace {
            label: "não".into(),
            result: result_of(&condition.evaluate(ctx, registry)),
            children: vec![trace_condition(cond, ctx, registry)],
        },
        Condition::All { of } | Condition::Any { of } => {
            let stop_on = matches!(condition, Condition::Any { .. });
            let mut children = Vec::with_capacity(of.len());
            let mut done = false;
            for child in of {
                if done {
                    children.push(skipped(child, ctx, registry));
                    continue;
                }
                let node = trace_condition(child, ctx, registry);
                done = match node.result {
                    TraceResult::True => stop_on,
                    TraceResult::False => !stop_on,
                    _ => true,
                };
                children.push(node);
            }
            ConditionTrace {
                label: if stop_on { "qualquer um" } else { "todos" }.into(),
                result: result_of(&condition.evaluate(ctx, registry)),
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
