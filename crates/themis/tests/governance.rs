//! Invariantes de mudança de grant e trilha de auditoria.

mod support;

use support::*;
use themis::{
    AUTHENTICATED, CatalogConformance, Forbid, Governance, Grant, Mutation, NoLockout, NoSelfManagement,
    RequirePermission, Subject, SubjectMatcher, TargetSelector,
};

fn admin() -> Subject {
    Subject::user("admin").with_role_in("admin", org())
}

fn base_grants() -> Vec<Grant> {
    vec![
        role_grant("admin-manage", "admin", "org.manage", true, at_org()),
        role_grant("member-view", "member", "project.view", true, at_org()),
    ]
}

fn governance(members: Vec<Subject>) -> Governance {
    Governance::new()
        .with(CatalogConformance)
        .with(RequirePermission::new("org.roles.edit", project()))
        .with(NoSelfManagement)
        .with(NoLockout::new(["org.invite"], members, project()))
        .with(Forbid::new(
            SubjectMatcher::principal(AUTHENTICATED),
            ["project.delete"],
        ))
}

#[test]
fn admin_grants_to_member_role() {
    let engine = engine();
    let add = Mutation::Add(role_grant("m-edit", "member", "project.edit", true, at_org()));
    let after = governance(vec![admin()])
        .apply(&engine, &admin(), &base_grants(), &add, None)
        .expect("mudança válida");
    assert_eq!(after.len(), 3);
}

#[test]
fn rejects_unknown_permission_and_bad_target() {
    let engine = engine();
    let gov = governance(vec![admin()]);
    let unknown = Mutation::Add(role_grant("x", "member", "project.nope", true, at_org()));
    let violations = gov
        .apply(&engine, &admin(), &base_grants(), &unknown, None)
        .unwrap_err();
    assert_eq!(violations[0].invariant, "catalog_conformance");

    let bad_target = Mutation::Add(role_grant(
        "y",
        "member",
        "org.manage",
        true,
        TargetSelector::exact("document", "d1"),
    ));
    assert!(gov.apply(&engine, &admin(), &base_grants(), &bad_target, None).is_err());
}

#[test]
fn member_without_permission_cannot_change_grants() {
    let engine = engine();
    let member = Subject::user("u1").with_role_in("member", org());
    let add = Mutation::Add(role_grant("m-edit", "member", "project.edit", true, at_org()));
    let violations = governance(vec![admin()])
        .apply(&engine, &member, &base_grants(), &add, None)
        .unwrap_err();
    assert!(violations.iter().any(|v| v.invariant == "require_permission"));
}

#[test]
fn nobody_manages_own_grants() {
    let engine = engine();
    let add = Mutation::Add(role_grant("self", "admin", "project.delete", false, at_org()));
    let violations = governance(vec![admin()])
        .apply(&engine, &admin(), &base_grants(), &add, None)
        .unwrap_err();
    assert!(violations.iter().any(|v| v.invariant == "no_self_management"));
}

#[test]
fn last_holder_of_critical_permission_cannot_be_removed() {
    let engine = engine();
    let other_admin = Subject::user("admin2").with_role_in("owner", org());
    let mut grants = base_grants();
    grants.push(role_grant("owner-manage", "owner", "org.manage", true, at_org()));

    let remove = Mutation::Remove {
        id: "admin-manage".into(),
    };
    let gov = governance(vec![admin()]);
    let violations = gov.apply(&engine, &other_admin, &grants, &remove, None).unwrap_err();
    assert!(violations.iter().any(|v| v.invariant == "no_lockout"));

    let gov = governance(vec![admin(), other_admin.clone()]);
    assert!(gov.apply(&engine, &other_admin, &grants, &remove, None).is_ok());
}

#[test]
fn forbidden_permission_is_refused_even_through_a_general_key() {
    let engine = engine();
    let gov = governance(vec![admin()]);
    for key in ["project.delete", "project.manage"] {
        let add = Mutation::Add(Grant::allow(
            "pub",
            SubjectMatcher::principal(AUTHENTICATED),
            key,
            TargetSelector::exact("project", PROJECT),
        ));
        let violations = gov.apply(&engine, &admin(), &base_grants(), &add, None).unwrap_err();
        assert!(violations.iter().any(|v| v.invariant == "forbid"));
    }
    let view = Mutation::Add(Grant::allow(
        "pub-view",
        SubjectMatcher::principal(AUTHENTICATED),
        "project.view",
        TargetSelector::exact("project", PROJECT),
    ));
    assert!(gov.apply(&engine, &admin(), &base_grants(), &view, None).is_ok());
}

#[test]
fn duplicate_and_missing_ids_are_rejected() {
    let engine = engine();
    let gov = Governance::new();
    let dup = Mutation::Add(base_grants()[0].clone());
    assert!(gov.apply(&engine, &admin(), &base_grants(), &dup, None).is_err());
    let missing = Mutation::Remove { id: "nope".into() };
    assert!(gov.apply(&engine, &admin(), &base_grants(), &missing, None).is_err());
}

#[cfg(feature = "audit")]
mod audit {
    use super::*;
    use std::sync::Arc;
    use themis::{Attributes, AuditError, AuditLevel, AuditOutcome, AuditRecord, Auditor, MemoryAuditLog};

    #[test]
    fn audited_governance_records_applied_and_rejected_changes() {
        let engine = engine();
        let log = Arc::new(MemoryAuditLog::new());
        let auditor = Arc::new(Auditor::new(AuditLevel::Detailed, log.clone()));
        let gov = governance(vec![admin()]).audited(auditor);
        let mut meta = Attributes::new();
        meta.insert("request_id".into(), "r-1".into());

        let ok = Mutation::Add(role_grant("m-edit", "member", "project.edit", true, at_org()));
        gov.apply_with(&engine, &admin(), &base_grants(), &ok, None, &meta)
            .unwrap();
        let bad = Mutation::Add(role_grant("self", "admin", "project.delete", false, at_org()));
        gov.apply(&engine, &admin(), &base_grants(), &bad, None).unwrap_err();

        let records = log.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].outcome, AuditOutcome::Applied);
        assert_eq!(records[0].meta.get("request_id"), Some(&"r-1".into()));
        assert!(records[0].full_grant.is_some());
        assert_eq!(records[1].outcome, AuditOutcome::Rejected);
        assert!(records[1].violations[0].contains("no_self_management"));
    }

    #[test]
    fn failing_audit_sink_blocks_the_change() {
        let engine = engine();
        let sink =
            Arc::new(|_: &AuditRecord| -> Result<(), AuditError> { Err(AuditError::Sink("disco cheio".into())) });
        let gov = governance(vec![admin()]).audited(Arc::new(Auditor::new(AuditLevel::Minimal, sink)));
        let ok = Mutation::Add(role_grant("m-edit", "member", "project.edit", true, at_org()));
        let violations = gov.apply(&engine, &admin(), &base_grants(), &ok, None).unwrap_err();
        assert_eq!(violations[0].invariant, "audit");
    }
}
