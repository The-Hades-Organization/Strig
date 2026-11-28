//! Textos curtos compartilhados pela janela e pelo terminal.

use std::fmt::Write;

use strig::{
    AuditRecord, Cause, Caveat, Change, ConditionTrace, Effect, Explanation, GrantTrace, OverrideOutcome, Reason,
    Remedies, SubjectMatcher, TraceResult, Verdict,
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
        Effect::Allow => "ALLOWED",
        Effect::Deny => "DENIED",
    }
}

pub fn reason(reason: &Reason) -> String {
    match reason {
        Reason::Override { name } => format!("override {name} decided before the grants"),
        Reason::Grant {
            grant_id,
            permission,
            rank,
            strategy,
        } => format!("grant {grant_id} ({permission}, step {rank}) chosen by strategy {strategy}"),
        Reason::NoApplicableGrant => "no grant applied: denied by default".into(),
        Reason::UnknownPermission => "the permission is not in the catalog".into(),
        Reason::MissingPrerequisite {
            permission,
            prerequisite,
        } => format!("{permission} requires {prerequisite}, which is not allowed on this resource"),
        _ => "not classified by this version".into(),
    }
}

pub fn matcher(subject: &SubjectMatcher) -> String {
    match subject {
        SubjectMatcher::User { id } => format!("user {id}"),
        SubjectMatcher::Role { id } => format!("role {id}"),
        SubjectMatcher::Principal { name } => format!("principal {name}"),
        SubjectMatcher::Relation { relation } => format!("relation {relation}"),
        SubjectMatcher::Any => "any subject".into(),
    }
}

pub fn verdict(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Candidate => "candidate".into(),
        Verdict::CandidateFailSafe { problem } => format!("candidate for safety (deny with an error: {problem})"),
        Verdict::PermissionUnrelated => "permission not related".into(),
        Verdict::OutsideWindow => "outside the validity window".into(),
        Verdict::OutOfScope => "scope is not on the resource path".into(),
        Verdict::TargetNotOnPath => "target matches no step".into(),
        Verdict::SubjectMismatch => "subject does not match".into(),
        Verdict::SubjectUnresolved { problem } => format!("allow dropped: subject cannot be evaluated ({problem})"),
        Verdict::ConditionFalse => "condition false".into(),
        Verdict::ConditionUnresolved { problem } => format!("allow dropped: condition cannot be evaluated ({problem})"),
        Verdict::OverrideOnly => "permission only holds through an override: grant ignored".into(),
        Verdict::FieldNotCovered => "the grant names fields and this one is not among them".into(),
        Verdict::NotReached => "not evaluated (an override decided first)".into(),
        _ => "not classified by this version".into(),
    }
}

pub fn override_outcome(outcome: OverrideOutcome) -> &'static str {
    match outcome {
        OverrideOutcome::Excepted => "out of reach (exception)",
        OverrideOutcome::Abstained => "abstained",
        OverrideOutcome::Allowed => "allowed",
        OverrideOutcome::Denied => "denied",
        _ => "not classified by this version",
    }
}

pub fn trace_mark(result: &TraceResult) -> &'static str {
    match result {
        TraceResult::True => "✔",
        TraceResult::False => "✘",
        TraceResult::Error(_) => "⚠",
        TraceResult::Skipped => "·",
        _ => "?",
    }
}

pub fn grant_line(trace: &GrantTrace) -> String {
    let g = &trace.grant;
    let target = match &g.target.id {
        Some(id) => format!("{}:{id}", g.target.kind),
        None => g.target.kind.clone(),
    };
    let rank = trace.rank.map(|r| format!(" [step {r}]")).unwrap_or_default();
    format!(
        "{} {} {} → {} on {}{}",
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

fn cause(cause: &Cause) -> String {
    match cause {
        Cause::Override { name } => format!("override {name} decided: no change of grants or roles undoes it"),
        Cause::Deny {
            grant_id, permission, ..
        } => format!("deny {grant_id} ({permission}) decided"),
        Cause::NoApplicableGrant => "no grant applied".into(),
        Cause::UnknownPermission => "the permission is not in the catalog".into(),
        Cause::OverrideOnlyPermission => "the permission only holds through an override".into(),
        Cause::MissingPrerequisite {
            prerequisite,
            cause: inner,
        } => {
            format!("prerequisite {prerequisite} is not allowed: {}", self::cause(inner))
        }
        _ => "not classified by this version".into(),
    }
}

fn change(change: &Change) -> String {
    match change {
        Change::AssignRole { role, scope } => match scope {
            Some(scope) => format!("assign role {role} within {scope}"),
            None => format!("assign role {role}"),
        },
        Change::AddGrant { grant } => format!(
            "add allow {} for {} on {}",
            grant.permission,
            matcher(&grant.subject),
            match &grant.target.id {
                Some(id) => format!("{}:{id}", grant.target.kind),
                None => grant.target.kind.clone(),
            }
        ),
        Change::RemoveDeny { grant_id, .. } => format!("remove deny {grant_id}"),
        Change::NarrowDeny { grant_id, field } => format!("take field {field} out of deny {grant_id}"),
        Change::SatisfyCondition {
            grant_id,
            failed,
            unresolved,
        } => {
            let all: Vec<&str> = failed.iter().chain(unresolved).map(String::as_str).collect();
            format!("make the condition of {grant_id} hold: {}", all.join("; "))
        }
        _ => "change not classified by this version".into(),
    }
}

fn caveat(caveat: &Caveat) -> &'static str {
    match caveat {
        Caveat::OverrideOnly => "override only",
        Caveat::ManagementOnly => "management roles only",
        Caveat::NonDelegable => "non-delegable",
        Caveat::AffectsOthers => "affects other subjects",
        _ => "other",
    }
}

/// "Why not" in text: the cause and each verified remedy, smallest first.
pub fn remedies(r: &Remedies) -> String {
    let mut out = format!("WHY NOT — {}\n", cause(&r.cause));
    if r.remedies.is_empty() {
        out.push_str("  no single change would allow it\n");
    }
    for (i, remedy) in r.remedies.iter().enumerate() {
        let notes: Vec<&str> = remedy.caveats.iter().map(caveat).collect();
        let notes = if notes.is_empty() {
            String::new()
        } else {
            format!(" [{}]", notes.join(", "))
        };
        let _ = writeln!(out, "  {}. {}{notes}", i + 1, change(&remedy.change));
    }
    if r.partial {
        out.push_str("  (partial: limit reached)\n");
    }
    out
}

/// Rastro completo em texto, para o terminal.
pub fn explanation(e: &Explanation) -> String {
    let mut out = String::new();
    let subject = e.subject.id.clone().unwrap_or_else(|| e.subject.kind.clone());
    let path: Vec<String> = e.path.iter().map(ToString::to_string).collect();
    let _ = writeln!(
        out,
        "{} — {subject} asks {} on {}",
        effect(e.decision.effect),
        e.permission,
        path.join(" → ")
    );
    let _ = writeln!(out, "reason: {}", reason(&e.decision.reason));
    if !e.effective.is_empty() {
        let _ = writeln!(out, "permissions that grant: {}", e.effective.join(", "));
    }
    let _ = writeln!(
        out,
        "effective roles: {}",
        if e.roles.is_empty() {
            "none".into()
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
        let _ = writeln!(out, "warning: {warning}");
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
            let cell = if m.cells[p][s] == Effect::Allow { "yes" } else { "no" };
            let flag = if m.changed(p, s) { "*" } else { " " };
            let _ = write!(out, "  {:>9}{flag}", cell);
        }
        out.push('\n');
    }
    if !m.changes().is_empty() {
        out.push_str("* changed from the original grants\n");
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
        ChainStatus::Absent => "no record at the forensic level: there is no hash chain to check".into(),
        ChainStatus::Intact { records } => match records {
            1 => "hash chain intact: 1 record at the forensic level".into(),
            n => format!("hash chain intact: {n} records at the forensic level"),
        },
        ChainStatus::Broken(error) => format!("hash chain BROKEN: {error}"),
    }
}

pub fn replay(replay: &Replay) -> String {
    let now = effect(replay.now.decision.effect);
    if replay.changed() {
        format!("recorded {:?}, today {now}: the decision CHANGED", replay.recorded)
    } else {
        format!("recorded {:?}, today {now}: same", replay.recorded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspector::tests::inspector;

    #[test]
    fn text_explanation_marks_decisive_grant_and_condition() {
        let inspector = inspector();
        let text = explanation(&inspector.explain_named("ben", "project.edit", "roadmap").unwrap());
        assert!(text.starts_with("DENIED"));
        assert!(text.contains("condition false"));
        assert!(text.contains(r#"✘ subject.plan ("free") = "pro""#));
        let text = explanation(&inspector.explain_named("ben", "document.view", "secret").unwrap());
        assert!(text.contains("★ no-secret deny"));
    }

    #[test]
    fn text_why_not_lists_verified_remedies_and_names_the_cause() {
        let inspector = inspector();
        let denied = inspector
            .why_not_named("ben", "project.edit", "roadmap")
            .unwrap()
            .expect("denied");
        let text = remedies(&denied);
        assert!(text.starts_with("WHY NOT — "), "{text}");
        assert!(text.contains("  1. "), "{text}");
    }
}
