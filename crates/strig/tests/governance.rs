//! Invariantes de mudança de grant e de papel, e trilha de auditoria.

mod support;

use strig::{
    AUTHENTICATED, Anchor, CatalogConformance, Forbid, Governance, Grant, Mutation, NoLockout, NoSelfManagement,
    Proposal, RequirePermission, RoleAssignment, Subject, SubjectMatcher, TargetSelector,
};
use support::*;

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

fn in_org(role: &str) -> RoleAssignment {
    RoleAssignment::in_scope(role, org())
}

fn assign(subject: Subject, role: RoleAssignment) -> Mutation {
    Mutation::AssignRole { subject, role }
}

fn revoke(subject: Subject, role: RoleAssignment) -> Mutation {
    Mutation::RevokeRole { subject, role }
}

fn invariants_of(violations: &[strig::Violation]) -> Vec<&str> {
    violations.iter().map(|v| v.invariant.as_str()).collect()
}

#[test]
fn admin_assigns_role_to_another_user() {
    let engine = engine();
    let mutation = assign(Subject::user("u1"), in_org("member"));
    let after = governance(vec![admin()])
        .apply(&engine, &admin(), &base_grants(), &mutation, None)
        .expect("atribuição válida");
    assert_eq!(after, base_grants());

    let subject = mutation.subject_after().expect("mudança de papel");
    assert_eq!(subject.roles, [in_org("member")]);

    let proposal = Proposal {
        actor: &admin(),
        mutation: &mutation,
        before: &after,
        after: &after,
        tuples: None,
        now: None,
    };
    assert!(proposal.grant().is_none());
    assert_eq!(proposal.subject_after(&Subject::user("u1")).roles, [in_org("member")]);
    assert_eq!(proposal.subject_after(&admin()).roles, admin().roles);
    assert_eq!(
        proposal.subject_after(&Subject::of_kind("service", "u1")).roles,
        [in_org("member")]
    );
    assert!(proposal.subject_after(&Subject::user("u2")).roles.is_empty());
}

#[test]
fn revoking_with_a_different_scope_is_rejected() {
    let engine = engine();
    let member = Subject::user("u1").with_role_in("member", org());
    let unscoped = RoleAssignment::new("member");
    let violations = Governance::new()
        .apply(
            &engine,
            &admin(),
            &base_grants(),
            &revoke(member.clone(), unscoped),
            None,
        )
        .unwrap_err();
    assert_eq!(invariants_of(&violations), ["mutation"]);
    assert!(
        Governance::new()
            .apply(
                &engine,
                &admin(),
                &base_grants(),
                &revoke(member, in_org("member")),
                None
            )
            .is_ok()
    );
}

#[test]
fn revoking_an_inherited_role_is_rejected() {
    let engine = engine();
    let gov = Governance::new();
    let holder = Subject::user("u1").with_role_in("admin", org());
    let violations = gov
        .apply(
            &engine,
            &admin(),
            &base_grants(),
            &revoke(holder.clone(), in_org("viewer")),
            None,
        )
        .unwrap_err();
    assert_eq!(invariants_of(&violations), ["mutation"]);
    assert!(
        gov.apply(
            &engine,
            &admin(),
            &base_grants(),
            &revoke(holder, in_org("admin")),
            None
        )
        .is_ok()
    );
}

#[test]
fn same_id_with_another_kind_is_the_same_subject() {
    let engine = engine();
    let alias = Subject::of_kind("service", "admin");
    let gov = governance(vec![admin()]);
    let violations = gov
        .apply(
            &engine,
            &admin(),
            &base_grants(),
            &assign(alias, in_org("member")),
            None,
        )
        .unwrap_err();
    assert!(invariants_of(&violations).contains(&"no_self_management"));

    let other_admin = Subject::user("admin2").with_role_in("admin", org());
    let alias = Subject::of_kind("service", "admin").with_role_in("admin", org());
    let violations = gov
        .apply(
            &engine,
            &other_admin,
            &base_grants(),
            &revoke(alias, in_org("admin")),
            None,
        )
        .unwrap_err();
    assert!(invariants_of(&violations).contains(&"no_lockout"));
}

#[test]
fn no_lockout_does_not_refuse_an_assignment() {
    let engine = engine();
    let gov = governance(vec![admin()]);
    let mutation = assign(Subject::user("u1"), in_org("member"));
    assert!(gov.apply(&engine, &admin(), &base_grants(), &mutation, None).is_ok());
}

#[test]
fn nobody_manages_own_roles() {
    let engine = engine();
    let mutation = assign(admin(), in_org("member"));
    let violations = governance(vec![admin()])
        .apply(&engine, &admin(), &base_grants(), &mutation, None)
        .unwrap_err();
    let ours: Vec<_> = violations
        .iter()
        .filter(|v| v.invariant == "no_self_management")
        .collect();
    assert_eq!(ours.len(), 1);
    assert_eq!(ours[0].message, "não é permitido gerenciar os próprios papéis");
}

#[test]
fn revoking_admin_from_last_member_is_a_lockout() {
    let engine = engine();
    let other_admin = Subject::user("admin2").with_role_in("admin", org());
    let mutation = revoke(admin(), in_org("admin"));
    let violations = governance(vec![admin()])
        .apply(&engine, &other_admin, &base_grants(), &mutation, None)
        .unwrap_err();
    assert_eq!(invariants_of(&violations), ["no_lockout"]);

    let gov = governance(vec![admin(), other_admin.clone()]);
    assert!(
        gov.apply(&engine, &other_admin, &base_grants(), &mutation, None)
            .is_ok()
    );
}

#[test]
fn rejects_unknown_role_and_scope_kind() {
    let engine = engine();
    let gov = governance(vec![admin()]);
    let unknown = assign(Subject::user("u1"), in_org("ghost"));
    let violations = gov
        .apply(&engine, &admin(), &base_grants(), &unknown, None)
        .unwrap_err();
    assert_eq!(invariants_of(&violations), ["catalog_conformance"]);

    let bad_scope = assign(
        Subject::user("u1"),
        RoleAssignment::in_scope("member", Anchor::new("planet", "earth")),
    );
    let violations = gov
        .apply(&engine, &admin(), &base_grants(), &bad_scope, None)
        .unwrap_err();
    assert_eq!(invariants_of(&violations), ["catalog_conformance"]);

    let cleanup = revoke(Subject::user("u1").with_role("ghost"), RoleAssignment::new("ghost"));
    assert!(gov.apply(&engine, &admin(), &base_grants(), &cleanup, None).is_ok());
}

#[test]
fn forbidden_user_cannot_receive_role_that_grants_forbidden_permission() {
    let engine = engine();
    let gov = governance(vec![admin()]).with(Forbid::new(SubjectMatcher::user("u1"), ["org.invite"]));
    let violations = gov
        .apply(
            &engine,
            &admin(),
            &base_grants(),
            &assign(Subject::user("u1"), in_org("admin")),
            None,
        )
        .unwrap_err();
    let forbid = violations.iter().find(|v| v.invariant == "forbid").expect("forbid");
    assert!(forbid.message.contains("admin") && forbid.message.contains("admin-manage"));
    assert!(forbid.message.contains("org.invite"));

    let member = assign(Subject::user("u1"), in_org("member"));
    assert!(gov.apply(&engine, &admin(), &base_grants(), &member, None).is_ok());
    let someone_else = assign(Subject::user("u2"), in_org("admin"));
    assert!(
        gov.apply(&engine, &admin(), &base_grants(), &someone_else, None)
            .is_ok()
    );
}

#[test]
fn duplicate_assignment_and_missing_revocation_are_rejected() {
    let engine = engine();
    let gov = Governance::new();
    let member = Subject::user("u1").with_role_in("member", org());
    let dup = assign(member.clone(), in_org("member"));
    let violations = gov.apply(&engine, &admin(), &base_grants(), &dup, None).unwrap_err();
    assert_eq!(invariants_of(&violations), ["mutation"]);

    let other_scope = assign(member.clone(), RoleAssignment::new("member"));
    assert!(gov.apply(&engine, &admin(), &base_grants(), &other_scope, None).is_ok());

    let missing = revoke(member, in_org("admin"));
    let violations = gov
        .apply(&engine, &admin(), &base_grants(), &missing, None)
        .unwrap_err();
    assert_eq!(invariants_of(&violations), ["mutation"]);

    let anonymous = assign(Subject::anonymous(), in_org("member"));
    let violations = gov
        .apply(&engine, &admin(), &base_grants(), &anonymous, None)
        .unwrap_err();
    assert_eq!(violations[0].message, "papel só se atribui a sujeito identificado");
}

#[cfg(feature = "audit")]
mod audit {
    use super::*;
    use std::sync::Arc;
    use strig::{Attributes, AuditAction, AuditError, AuditLevel, AuditOutcome, AuditRecord, Auditor, MemoryAuditLog};

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

    #[test]
    fn audited_governance_records_role_changes() {
        let engine = engine();
        let log = Arc::new(MemoryAuditLog::new());
        let auditor = Arc::new(Auditor::new(AuditLevel::Detailed, log.clone()));
        let gov = governance(vec![admin()]).audited(auditor);
        let mut meta = Attributes::new();
        meta.insert("request_id".into(), "r-2".into());

        let ok = assign(Subject::user("u1"), in_org("member"));
        gov.apply_with(&engine, &admin(), &base_grants(), &ok, None, &meta)
            .unwrap();
        let other_admin = Subject::user("admin2").with_role_in("admin", org());
        let bad = revoke(admin(), in_org("admin"));
        gov.apply(&engine, &other_admin, &base_grants(), &bad, None)
            .unwrap_err();

        let records = log.records();
        assert_eq!(records.len(), 2);
        let applied = &records[0];
        assert_eq!(applied.action, AuditAction::RoleAssign);
        assert_eq!(applied.outcome, AuditOutcome::Applied);
        assert_eq!(applied.object, "member#org:o1@u1");
        let role = applied.role.as_ref().expect("resumo do papel");
        assert_eq!((role.subject.as_str(), role.role.as_str()), ("u1", "member"));
        assert_eq!(role.scope, Some(org()));
        assert!(applied.violations.is_empty() && applied.grant.is_none());
        assert_eq!(applied.meta.get("request_id"), Some(&"r-2".into()));
        assert_eq!(
            applied.actor_detail.as_ref().and_then(|a| a.id.as_deref()),
            Some("admin")
        );

        let rejected = &records[1];
        assert_eq!(rejected.action, AuditAction::RoleRevoke);
        assert_eq!(rejected.outcome, AuditOutcome::Rejected);
        assert_eq!(rejected.object, "admin#org:o1@admin");
        assert_eq!(rejected.actor, "admin2");
        assert_eq!(rejected.violations.len(), 1);
        assert!(rejected.violations[0].starts_with("[no_lockout] "));
    }

    #[test]
    fn standard_level_keeps_only_violation_names_for_roles() {
        let engine = engine();
        let log = Arc::new(MemoryAuditLog::new());
        let gov = governance(vec![admin()]).audited(Arc::new(Auditor::new(AuditLevel::Standard, log.clone())));
        gov.apply(
            &engine,
            &admin(),
            &base_grants(),
            &assign(admin(), in_org("member")),
            None,
        )
        .unwrap_err();
        let record = &log.records()[0];
        assert_eq!(record.violations, ["no_self_management"]);
        assert!(record.actor_detail.is_none());
    }

    #[test]
    fn forensic_chain_mixes_grant_and_role_records_with_digests() {
        let engine = engine();
        let log = Arc::new(MemoryAuditLog::new());
        let gov = governance(vec![admin()]).audited(Arc::new(Auditor::new(AuditLevel::Forensic, log.clone())));
        let meta = Attributes::new();

        let add = Mutation::Add(role_grant("m-edit", "member", "project.edit", true, at_org()));
        gov.apply_with(&engine, &admin(), &base_grants(), &add, None, &meta)
            .unwrap();
        let holder = Subject::user("u1").with_role_in("viewer", org()).with_role("beta");
        let applied = assign(holder.clone(), in_org("member"));
        gov.apply_with(&engine, &admin(), &base_grants(), &applied, None, &meta)
            .unwrap();
        let refused = assign(admin(), in_org("member"));
        gov.apply_with(&engine, &admin(), &base_grants(), &refused, None, &meta)
            .unwrap_err();

        let records = log.records();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].action, AuditAction::GrantAdd);
        strig::audit::verify_chain(&records).expect("cadeia íntegra");

        let role = &records[1];
        assert_eq!(role.action, AuditAction::RoleAssign);
        assert_eq!(role.object, "member#org:o1@u1");
        let (before, after) = (role.before_digest.clone().unwrap(), role.after_digest.clone().unwrap());
        assert_ne!(before, after);

        let rejected = &records[2];
        assert_eq!(rejected.outcome, AuditOutcome::Rejected);
        assert_eq!(rejected.before_digest, rejected.after_digest);
        assert!(rejected.before_digest.is_some());
    }

    #[test]
    fn role_digest_ignores_order() {
        let engine = engine();
        let log = Arc::new(MemoryAuditLog::new());
        let gov = governance(vec![admin()]).audited(Arc::new(Auditor::new(AuditLevel::Forensic, log.clone())));
        let a = Subject::user("u1").with_role("beta").with_role_in("viewer", org());
        let b = Subject::user("u1").with_role_in("viewer", org()).with_role("beta");
        for subject in [a, b] {
            gov.apply(
                &engine,
                &admin(),
                &base_grants(),
                &assign(subject, in_org("member")),
                None,
            )
            .unwrap();
        }
        let records = log.records();
        assert_eq!(records[0].before_digest, records[1].before_digest);
        assert_eq!(records[0].after_digest, records[1].after_digest);
    }

    #[test]
    fn rejected_role_record_by_level() {
        let engine = engine();
        for (level, expected) in [
            (AuditLevel::Standard, "no_self_management"),
            (
                AuditLevel::Detailed,
                "[no_self_management] não é permitido gerenciar os próprios papéis",
            ),
        ] {
            let log = Arc::new(MemoryAuditLog::new());
            let gov = governance(vec![admin()]).audited(Arc::new(Auditor::new(level, log.clone())));
            gov.apply(
                &engine,
                &admin(),
                &base_grants(),
                &assign(admin(), in_org("member")),
                None,
            )
            .unwrap_err();
            let record = &log.records()[0];
            assert_eq!(record.action, AuditAction::RoleAssign);
            assert_eq!(record.outcome, AuditOutcome::Rejected);
            assert_eq!(record.violations, [expected]);
            assert!(record.before_digest.is_none());
        }
    }

    #[test]
    fn anonymous_role_subject_is_marked() {
        let engine = engine();
        let log = Arc::new(MemoryAuditLog::new());
        let gov = Governance::new().audited(Arc::new(Auditor::new(AuditLevel::Standard, log.clone())));
        gov.apply(
            &engine,
            &admin(),
            &base_grants(),
            &assign(Subject::anonymous(), in_org("member")),
            None,
        )
        .unwrap_err();
        let record = &log.records()[0];
        assert_eq!(record.role.as_ref().unwrap().subject, "user:<anonymous>");
    }

    #[test]
    fn failing_audit_sink_blocks_role_change() {
        let engine = engine();
        let sink =
            Arc::new(|_: &AuditRecord| -> Result<(), AuditError> { Err(AuditError::Sink("disco cheio".into())) });
        let gov = governance(vec![admin()]).audited(Arc::new(Auditor::new(AuditLevel::Minimal, sink)));
        let ok = assign(Subject::user("u1"), in_org("member"));
        let violations = gov.apply(&engine, &admin(), &base_grants(), &ok, None).unwrap_err();
        assert_eq!(invariants_of(&violations), ["audit"]);
    }
}
