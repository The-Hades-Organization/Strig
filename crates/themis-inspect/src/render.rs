//! Textos curtos compartilhados pela janela e pelo terminal.

use std::fmt::Write;

use themis::{
    AuditRecord, ConditionTrace, Effect, Explanation, GrantTrace, OverrideOutcome, Reason, SubjectMatcher, TraceResult,
    Verdict,
};

use crate::inspector::Matrix;
use crate::trail::{ChainStatus, Replay};

/// A palavra do efeito como no catálogo: `allow` ou `deny`.
pub fn effect_word(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
    }
}

pub fn effect(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "PERMITIDO",
        Effect::Deny => "NEGADO",
    }
}

pub fn reason(reason: &Reason) -> String {
    match reason {
        Reason::Override { name } => format!("o override {name} decidiu antes dos grants"),
        Reason::Grant {
            grant_id,
            permission,
            rank,
            strategy,
        } => format!("grant {grant_id} ({permission}, degrau {rank}) escolhido pela estratégia {strategy}"),
        Reason::NoApplicableGrant => "nenhum grant se aplicou: negado por padrão".into(),
        Reason::UnknownPermission => "a permissão não existe no catálogo".into(),
        Reason::MissingPrerequisite {
            permission,
            prerequisite,
        } => format!("{permission} exige {prerequisite}, que não é permitida neste recurso"),
    }
}

pub fn matcher(subject: &SubjectMatcher) -> String {
    match subject {
        SubjectMatcher::User { id } => format!("usuário {id}"),
        SubjectMatcher::Role { id } => format!("papel {id}"),
        SubjectMatcher::Principal { name } => format!("principal {name}"),
        SubjectMatcher::Relation { relation } => format!("relação {relation}"),
        SubjectMatcher::Any => "qualquer sujeito".into(),
    }
}

pub fn verdict(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Candidate => "candidato".into(),
        Verdict::CandidateFailSafe { problem } => format!("candidato por segurança (deny com erro: {problem})"),
        Verdict::PermissionUnrelated => "permissão não relacionada".into(),
        Verdict::OutOfScope => "escopo fora do caminho do recurso".into(),
        Verdict::TargetNotOnPath => "alvo não casa nenhum degrau".into(),
        Verdict::SubjectMismatch => "sujeito não casa".into(),
        Verdict::SubjectUnresolved { problem } => format!("allow descartado: sujeito não avaliável ({problem})"),
        Verdict::ConditionFalse => "condição falsa".into(),
        Verdict::ConditionUnresolved { problem } => format!("allow descartado: condição não avaliável ({problem})"),
        Verdict::OverrideOnly => "permissão só vale por override: grant ignorado".into(),
        Verdict::NotReached => "não avaliado (override decidiu antes)".into(),
    }
}

pub fn override_outcome(outcome: OverrideOutcome) -> &'static str {
    match outcome {
        OverrideOutcome::Excepted => "fora do alcance (exceção)",
        OverrideOutcome::Abstained => "não se pronunciou",
        OverrideOutcome::Allowed => "permitiu",
        OverrideOutcome::Denied => "negou",
    }
}

pub fn trace_mark(result: &TraceResult) -> &'static str {
    match result {
        TraceResult::True => "✔",
        TraceResult::False => "✘",
        TraceResult::Error(_) => "⚠",
        TraceResult::Skipped => "·",
    }
}

pub fn grant_line(trace: &GrantTrace) -> String {
    let g = &trace.grant;
    let target = match &g.target.id {
        Some(id) => format!("{}:{id}", g.target.kind),
        None => g.target.kind.clone(),
    };
    let rank = trace.rank.map(|r| format!(" [degrau {r}]")).unwrap_or_default();
    format!(
        "{} {} {} → {} em {}{}",
        g.id,
        if g.effect == Effect::Allow { "allow" } else { "deny" },
        g.permission,
        matcher(&g.subject),
        target,
        rank
    )
}

fn write_condition(out: &mut String, node: &ConditionTrace, depth: usize) {
    let detail = match &node.result {
        TraceResult::Error(e) => format!("  ({e})"),
        _ => String::new(),
    };
    let _ = writeln!(
        out,
        "{}{} {}{}",
        "    ".repeat(depth + 2),
        trace_mark(&node.result),
        node.label,
        detail
    );
    for child in &node.children {
        write_condition(out, child, depth + 1);
    }
}

/// Rastro completo em texto, para o terminal.
pub fn explanation(e: &Explanation) -> String {
    let mut out = String::new();
    let subject = e.subject.id.clone().unwrap_or_else(|| e.subject.kind.clone());
    let path: Vec<String> = e.path.iter().map(ToString::to_string).collect();
    let _ = writeln!(
        out,
        "{} — {subject} pede {} em {}",
        effect(e.decision.effect),
        e.permission,
        path.join(" → ")
    );
    let _ = writeln!(out, "motivo: {}", reason(&e.decision.reason));
    if !e.effective.is_empty() {
        let _ = writeln!(out, "permissões que concedem: {}", e.effective.join(", "));
    }
    let _ = writeln!(
        out,
        "papéis efetivos: {}",
        if e.roles.is_empty() {
            "nenhum".into()
        } else {
            e.roles.join(", ")
        }
    );
    for step in &e.overrides {
        let _ = writeln!(out, "override {}: {}", step.name, override_outcome(step.outcome));
    }
    let decisive = e.decisive().map(|g| g.grant.id.clone());
    let _ = writeln!(out, "grants ({}):", e.grants.len());
    for trace in &e.grants {
        let mark = if decisive.as_deref() == Some(trace.grant.id.as_str()) {
            "★"
        } else if trace.verdict.is_candidate() {
            "+"
        } else {
            "-"
        };
        let _ = writeln!(out, "  {mark} {}", grant_line(trace));
        let _ = writeln!(out, "      {}", verdict(&trace.verdict));
        if let Some(condition) = &trace.condition {
            write_condition(&mut out, condition, 0);
        }
    }
    for warning in &e.decision.warnings {
        let _ = writeln!(out, "aviso: {warning}");
    }
    out
}

pub fn matrix(m: &Matrix) -> String {
    let width = m.permissions.iter().map(String::len).max().unwrap_or(0).max(10);
    let mut out = format!("{:width$}", format!("[{}]", m.resource));
    for subject in &m.subjects {
        let _ = write!(out, "  {subject:>10}");
    }
    out.push('\n');
    for (p, permission) in m.permissions.iter().enumerate() {
        let _ = write!(out, "{permission:width$}");
        for s in 0..m.subjects.len() {
            let cell = if m.cells[p][s] == Effect::Allow { "sim" } else { "não" };
            let flag = if m.changed(p, s) { "*" } else { " " };
            let _ = write!(out, "  {:>9}{flag}", cell);
        }
        out.push('\n');
    }
    if !m.changes().is_empty() {
        out.push_str("* mudou em relação aos grants originais\n");
    }
    out
}

pub fn record_line(record: &AuditRecord) -> String {
    format!(
        "{} {:?} {} {} → {:?} [{}]",
        record.at, record.action, record.actor, record.object, record.outcome, record.level
    )
}

pub fn chain(status: &ChainStatus) -> String {
    match status {
        ChainStatus::Absent => "nenhum registro no nível forensic: não há cadeia de hashes para conferir".into(),
        ChainStatus::Intact { records } => match records {
            1 => "cadeia de hashes íntegra: 1 registro no nível forensic".into(),
            n => format!("cadeia de hashes íntegra: {n} registros no nível forensic"),
        },
        ChainStatus::Broken(error) => format!("cadeia de hashes QUEBRADA: {error}"),
    }
}

pub fn replay(replay: &Replay) -> String {
    let now = effect(replay.now.decision.effect);
    if replay.changed() {
        format!("registrado {:?}, hoje {now}: a decisão MUDOU", replay.recorded)
    } else {
        format!("registrado {:?}, hoje {now}: igual", replay.recorded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspector::tests::inspector;

    #[test]
    fn text_explanation_marks_decisive_grant_and_condition() {
        let inspector = inspector();
        let text = explanation(&inspector.explain_named("beto", "project.edit", "roadmap").unwrap());
        assert!(text.starts_with("NEGADO"));
        assert!(text.contains("condição falsa"));
        assert!(text.contains(r#"✘ subject.plan ("free") = "pro""#));
        let text = explanation(&inspector.explain_named("beto", "document.view", "secret").unwrap());
        assert!(text.contains("★ no-secret deny"));
    }
}
