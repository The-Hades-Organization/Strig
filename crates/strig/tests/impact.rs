//! Impacto de uma mudança antes de aplicá-la: quem ganha, quem perde, o que não se decide, o corte por
//! limite, o pedido de aprovação e o resumo na auditoria.

use strig::{
    Access, ApprovalPolicy, Approvals, Attributes, Catalog, Condition, Engine, Governance, Grant, Impact,
    ImpactOptions, ImpactSource, MemoryPendingStore, Mutation, MutationKind, Operand, PendingRequest, PendingStore,
    PermissionDef, Proposed, QueryLimits, Resource, Review, RoleAssignment, SampleSpec, Subject, SubjectMatcher,
    TargetSelector,
};

fn engine() -> Engine {
    let catalog = Catalog::builder()
        .target_kinds(["document", "project"])
        .permission(PermissionDef::new("document.view").targets(["document", "project"]))
        .permission(
            PermissionDef::new("document.edit")
                .targets(["document", "project"])
                .implied_by(["document.manage"])
                .depends_on(["document.view"]),
        )
        .permission(PermissionDef::new("document.manage").targets(["document", "project"]))
        .permission(PermissionDef::new("access.approve").targets(["project"]))
        .build()
        .expect("catálogo");
    Engine::builder(catalog).build().expect("motor")
}

fn project() -> TargetSelector {
    TargetSelector::exact("project", "p1")
}

fn doc() -> Resource {
    Resource::new("document", "d1").within("project", "p1")
}

fn project_resource() -> Resource {
    Resource::new("project", "p1")
}

fn view_for_editor() -> Grant {
    Grant::allow(
        "editor-view",
        SubjectMatcher::role("editor"),
        "document.view",
        project(),
    )
}

fn ana() -> Subject {
    Subject::user("ana").with_role("editor")
}

fn derived() -> ImpactOptions<'static> {
    ImpactOptions::new(ImpactSource::derived())
}

fn sample(subjects: impl IntoIterator<Item = Subject>) -> ImpactOptions<'static> {
    let spec = subjects.into_iter().fold(SampleSpec::new(), SampleSpec::subject);
    ImpactOptions::new(ImpactSource::sample(spec.resource(doc())))
}

fn impact(current: &[Grant], mutation: &Mutation, options: &ImpactOptions<'_>) -> Impact {
    Governance::new()
        .impact(&engine(), &Subject::user("root"), current, mutation, options)
        .expect("a mudança passa")
}

fn names(list: &[strig::AccessChange]) -> Vec<String> {
    list.iter().map(|c| format!("{} {}", c.subject, c.permission)).collect()
}

#[test]
fn a_new_allow_shows_who_gains_it() {
    let result = impact(&[], &Mutation::Add(view_for_editor()), &derived());
    assert_eq!(names(&result.gained), ["role:editor document.view"]);
    assert!(result.lost.is_empty() && result.indeterminate.is_empty() && !result.partial);
    assert_eq!(result.gained[0].before, Access::Denied);
    assert_eq!(result.gained[0].after, Access::Allowed);
    assert_eq!(result.gained[0].resource, project_resource());
}

#[test]
fn removing_an_allow_shows_who_loses_it() {
    let current = [view_for_editor()];
    let result = impact(
        &current,
        &Mutation::Remove {
            id: "editor-view".into(),
        },
        &derived(),
    );
    assert_eq!(names(&result.lost), ["role:editor document.view"]);
    assert!(result.gained.is_empty());
}

#[test]
fn a_deny_that_cuts_shows_the_loss_of_a_sampled_subject() {
    let current = [view_for_editor()];
    let deny = Grant::deny("no-ana", SubjectMatcher::user("ana"), "document.view", project());
    let result = impact(
        &current,
        &Mutation::Add(deny),
        &sample([ana(), Subject::user("bia").with_role("editor")]),
    );
    assert_eq!(names(&result.lost), ["user:ana document.view"]);
    assert!(result.gained.is_empty(), "bia keeps what she had");
}

#[test]
fn implied_and_dependent_permissions_are_part_of_the_impact() {
    let current = [view_for_editor()];
    let manage = Grant::allow(
        "editor-manage",
        SubjectMatcher::role("editor"),
        "document.manage",
        project(),
    );
    let result = impact(&current, &Mutation::Add(manage), &derived());
    assert_eq!(
        names(&result.gained),
        ["role:editor document.edit", "role:editor document.manage"]
    );
    assert!(result.permissions.contains(&"document.edit".to_string()));
}

#[test]
fn a_grant_with_fields_moves_only_those_fields() {
    let current = [view_for_editor()];
    let edit_title =
        Grant::allow("edit-title", SubjectMatcher::role("editor"), "document.edit", project()).fields(["title"]);
    let result = impact(&current, &Mutation::Add(edit_title), &sample([ana()]));
    assert_eq!(result.gained.len(), 1, "{result:?}");
    assert_eq!(result.gained[0].field.as_deref(), Some("title"));
    assert_eq!(result.gained[0].permission, "document.edit");
}

fn pro_only() -> Grant {
    Grant::allow("pro-edit", SubjectMatcher::role("editor"), "document.view", project())
        .when(Condition::eq(Operand::attr("subject.plan"), Operand::lit("pro")))
}

#[test]
fn a_condition_that_cannot_be_evaluated_is_undetermined_never_a_gain() {
    let result = impact(&[], &Mutation::Add(pro_only()), &sample([ana()]));
    assert!(result.gained.is_empty(), "{result:?}");
    assert_eq!(names(&result.indeterminate), ["user:ana document.view"]);
    assert_eq!(result.indeterminate[0].after, Access::Indeterminate);
}

#[test]
fn the_same_condition_is_a_gain_when_the_subject_carries_the_attribute() {
    let pro = ana().with_attr("plan", "pro");
    let result = impact(&[], &Mutation::Add(pro_only()), &sample([pro]));
    assert_eq!(names(&result.gained), ["user:ana document.view"]);
    assert!(result.indeterminate.is_empty());
}

#[test]
fn a_condition_that_evaluates_false_changes_nothing() {
    let free = ana().with_attr("plan", "free");
    let result = impact(&[], &Mutation::Add(pro_only()), &sample([free]));
    assert!(result.is_empty(), "{result:?}");
}

#[test]
fn a_role_change_shows_what_the_subject_gets() {
    let current = [view_for_editor()];
    let bob = Subject::user("bob");
    let mutation = Mutation::AssignRole {
        subject: bob,
        role: RoleAssignment::new("editor"),
    };
    let result = impact(&current, &mutation, &derived());
    assert_eq!(names(&result.gained), ["user:bob document.view"]);
}

#[test]
fn a_limit_cuts_the_answer_and_says_so() {
    let limits = QueryLimits::default().with_max_decisions(2);
    let manage = Grant::allow(
        "editor-manage",
        SubjectMatcher::role("editor"),
        "document.manage",
        project(),
    );
    let options = derived().with_limits(limits);
    let result = impact(&[view_for_editor()], &Mutation::Add(manage), &options);
    assert!(result.partial, "{result:?}");
    assert!(result.checked <= 2);
    assert!(result.notes.iter().any(|n| n.contains("decisions")));
}

#[test]
fn a_refused_change_has_no_impact() {
    let governance = Governance::new().with(strig::CatalogConformance);
    let unknown = Grant::allow("x", SubjectMatcher::role("editor"), "nope.nothing", project());
    let refused = governance.impact(
        &engine(),
        &Subject::user("root"),
        &[],
        &Mutation::Add(unknown),
        &derived(),
    );
    assert!(refused.is_err());
}

fn approver_grant() -> Grant {
    Grant::allow("boss", SubjectMatcher::user("boss"), "access.approve", project())
}

#[test]
fn the_approver_sees_the_impact_recomputed_over_the_grants_as_they_are_now() {
    let engine = engine();
    let governance = Governance::new();
    let policy = ApprovalPolicy::new().require(MutationKind::Add, "access.approve", project_resource());
    let store = MemoryPendingStore::new();
    let options = derived();
    let flow = Approvals::new(&governance, &policy, &store).with_impact(&options);
    let meta = Attributes::new();
    let before = vec![approver_grant()];
    let review = |grants: &'static [Grant], now| Review::new(&engine, grants, now, &meta);
    let leaked: &'static [Grant] = Box::leak(before.clone().into_boxed_slice());
    let mutation = Mutation::Add(view_for_editor());
    let Proposed::Pending(pending) = flow
        .propose(&review(leaked, 10), &Subject::user("ana"), &mutation, "r1", None)
        .unwrap()
    else {
        panic!("a política pede aprovação")
    };
    let proposed = pending.impact.clone().expect("o pedido guarda o impacto");
    assert_eq!(names(&proposed.gained), ["role:editor document.view"]);
    assert_eq!(store.get("r1").unwrap().unwrap().impact, Some(proposed.clone()));

    let mut later = before.clone();
    later.push(Grant::allow(
        "editor-view-too",
        SubjectMatcher::role("editor"),
        "document.view",
        project(),
    ));
    let leaked_later: &'static [Grant] = Box::leak(later.into_boxed_slice());
    let seen = flow.review_impact(&review(leaked_later, 20), "r1").unwrap();
    assert!(seen.changed, "o estado mudou desde a proposta");
    assert_eq!(seen.proposed, Some(proposed.clone()));
    assert!(seen.current.as_ref().unwrap().gained.is_empty(), "o editor já via");

    let approved = flow
        .approve(&review(leaked_later, 30), &Subject::user("boss"), "r1")
        .unwrap();
    assert_eq!(approved.proposed_impact, Some(proposed));
    assert!(approved.request.impact.unwrap().gained.is_empty());
}

#[test]
fn a_request_from_before_the_impact_still_reads_and_writes_without_it() {
    let json = r#"{"id":"r","actor":{"kind":"user","id":"ana"},"mutation":{"remove":{"id":"g"}},"requestedAt":1,"status":{"state":"pending"}}"#;
    let request: PendingRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.impact, None);
    assert!(!serde_json::to_string(&request).unwrap().contains("impact"));
}

#[test]
fn the_impact_survives_the_json_of_a_stored_request() {
    let result = impact(&[], &Mutation::Add(view_for_editor()), &derived());
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"gained\""));
    assert_eq!(serde_json::from_str::<Impact>(&json).unwrap(), result);
}

#[cfg(feature = "audit")]
mod audit {
    use std::sync::Arc;

    use strig::audit::{AuditLevel, Auditor, MemoryAuditLog, verify_chain};

    use super::*;

    fn run(level: AuditLevel) -> Vec<strig::audit::AuditRecord> {
        let log = Arc::new(MemoryAuditLog::new());
        let governance = Governance::new().audited(Arc::new(Auditor::new(level, log.clone())));
        let applied = governance
            .apply_with_impact(
                &engine(),
                &Subject::user("root"),
                &[],
                &Mutation::Add(view_for_editor()),
                None,
                &Attributes::new(),
                &derived(),
            )
            .unwrap();
        assert_eq!(applied.impact.gained.len(), 1);
        log.records()
    }

    #[test]
    fn detailed_keeps_a_summary_of_the_impact() {
        let records = run(AuditLevel::Detailed);
        let summary = records[0].impact.as_ref().expect("resumo do impacto");
        assert_eq!((summary.gained, summary.lost, summary.indeterminate), (1, 0, 0));
        assert_eq!(summary.examples, ["gained role:editor document.view project:p1"]);
    }

    #[test]
    fn standard_and_below_leave_it_out() {
        assert!(run(AuditLevel::Standard)[0].impact.is_none());
        assert!(run(AuditLevel::Minimal)[0].impact.is_none());
    }

    #[test]
    fn forensic_chain_still_verifies_with_the_impact_in_the_record() {
        let records = run(AuditLevel::Forensic);
        assert!(records[0].impact.is_some());
        assert!(verify_chain(&records).is_ok());
    }
}
