//! Attribute invariants (non-delegable, management-only), escalation and the lockout suggestion.

use themis::{
    Anchor, Bypass, Catalog, Engine, Forbid, Governance, Grant, ManagementOnly, Mutation, NoEscalation, NoLockout,
    NoSelfManagement, NonDelegable, PermissionDef, Resource, RoleAssignment, Subject, SubjectMatcher, Suggestion,
    TargetSelector,
};

fn engine() -> Engine {
    let catalog = Catalog::builder()
        .target_kind("project")
        .permission(PermissionDef::new("project.view").targets(["project"]))
        .permission(PermissionDef::new("project.edit").targets(["project"]))
        .permission(PermissionDef::new("project.manage").targets(["project"]))
        .permission(PermissionDef::new("project.admin").targets(["project"]).non_delegable())
        .permission(
            PermissionDef::new("project.billing")
                .targets(["project"])
                .management_only(),
        )
        .build()
        .expect("catalog");
    Engine::builder(catalog).build().expect("engine")
}

fn project() -> Resource {
    Resource::new("project", "p1")
}

fn on_projects() -> TargetSelector {
    TargetSelector::kind("project")
}

fn user_grant(id: &str, user: &str, key: &str) -> Grant {
    Grant::allow(id, SubjectMatcher::user(user), key, on_projects())
}

fn role_grant(id: &str, role: &str, key: &str) -> Grant {
    Grant::allow(id, SubjectMatcher::role(role), key, on_projects())
}

fn role(name: &str) -> RoleAssignment {
    RoleAssignment::new(name)
}

fn invariant_of(result: Result<Vec<Grant>, Vec<themis::Violation>>) -> String {
    result.expect_err("refused").remove(0).invariant
}

#[test]
fn non_delegable_is_granted_only_by_the_manager() {
    let engine = engine();
    let governance = Governance::new().with(NonDelegable::new("project.manage"));
    let grants = vec![
        user_grant("h", "holder", "project.admin"),
        user_grant("m", "manager", "project.manage"),
    ];
    let add = Mutation::Add(user_grant("new", "ana", "project.admin"));

    let holder = Subject::user("holder");
    assert_eq!(
        invariant_of(governance.apply(&engine, &holder, &grants, &add, None)),
        "non_delegable"
    );

    let manager = Subject::user("manager");
    governance
        .apply(&engine, &manager, &grants, &add, None)
        .expect("manager may delegate");

    let plain = Mutation::Add(user_grant("v", "ana", "project.view"));
    governance
        .apply(&engine, &holder, &grants, &plain, None)
        .expect("other permissions are free");
}

#[test]
fn non_delegable_covers_role_assignment() {
    let engine = engine();
    let governance = Governance::new().with(NonDelegable::new("project.manage"));
    let grants = vec![
        user_grant("h", "holder", "project.admin"),
        user_grant("m", "manager", "project.manage"),
        role_grant("r", "owners", "project.admin"),
    ];
    let assign = Mutation::AssignRole {
        subject: Subject::user("ana"),
        role: role("owners"),
    };
    assert_eq!(
        invariant_of(governance.apply(&engine, &Subject::user("holder"), &grants, &assign, None)),
        "non_delegable"
    );
    governance
        .apply(&engine, &Subject::user("manager"), &grants, &assign, None)
        .expect("manager may assign");
}

#[test]
fn management_only_goes_to_management_roles() {
    let engine = engine();
    let governance = Governance::new().with(ManagementOnly::new(["finance"]));
    let actor = Subject::user("boss");

    for subject in [
        SubjectMatcher::user("ana"),
        SubjectMatcher::principal("authenticated"),
        SubjectMatcher::role("ordinary"),
    ] {
        let add = Mutation::Add(Grant::allow("b", subject, "project.billing", on_projects()));
        assert_eq!(
            invariant_of(governance.apply(&engine, &actor, &[], &add, None)),
            "management_only"
        );
    }

    let to_finance = Mutation::Add(role_grant("b", "finance", "project.billing"));
    governance
        .apply(&engine, &actor, &[], &to_finance, None)
        .expect("management role");
}

#[test]
fn management_only_refuses_assigning_an_ordinary_role_that_carries_it() {
    let engine = engine();
    let governance = Governance::new().with(ManagementOnly::new(["finance"]));
    let grants = vec![
        role_grant("o", "ordinary", "project.billing"),
        role_grant("f", "finance", "project.billing"),
    ];
    let actor = Subject::user("boss");
    let ana = Subject::user("ana");
    let ordinary = Mutation::AssignRole {
        subject: ana.clone(),
        role: role("ordinary"),
    };
    assert_eq!(
        invariant_of(governance.apply(&engine, &actor, &grants, &ordinary, None)),
        "management_only"
    );
    let finance = Mutation::AssignRole {
        subject: ana,
        role: role("finance"),
    };
    governance
        .apply(&engine, &actor, &grants, &finance, None)
        .expect("management role");
}

#[test]
fn no_escalation_limits_grants_to_what_the_actor_holds() {
    let engine = engine();
    let governance = Governance::new().with(NoEscalation::new());
    let grants = vec![user_grant("l", "lead", "project.view")];
    let lead = Subject::user("lead");

    let view = Mutation::Add(user_grant("a", "ana", "project.view"));
    governance
        .apply(&engine, &lead, &grants, &view, None)
        .expect("holds view");

    let edit = Mutation::Add(user_grant("b", "ana", "project.edit"));
    assert_eq!(
        invariant_of(governance.apply(&engine, &lead, &grants, &edit, None)),
        "no_escalation"
    );
}

#[test]
fn no_escalation_checks_the_permissions_of_an_assigned_role() {
    let engine = engine();
    let governance = Governance::new().with(NoEscalation::new());
    let grants = vec![
        user_grant("l", "lead", "project.view"),
        role_grant("v", "viewers", "project.view"),
        role_grant("e", "editors", "project.edit"),
    ];
    let lead = Subject::user("lead");
    let ana = Subject::user("ana");
    let editors = Mutation::AssignRole {
        subject: ana.clone(),
        role: role("editors"),
    };
    assert_eq!(
        invariant_of(governance.apply(&engine, &lead, &grants, &editors, None)),
        "no_escalation"
    );
    let viewers = Mutation::AssignRole {
        subject: ana,
        role: role("viewers"),
    };
    governance
        .apply(&engine, &lead, &grants, &viewers, None)
        .expect("holds everything in the role");
}

#[test]
fn no_escalation_does_not_reach_the_role_in_another_scope() {
    let engine = engine();
    let governance = Governance::new().with(NoEscalation::new());
    let grants = vec![
        Grant::allow("l", SubjectMatcher::user("lead"), "project.edit", on_projects()).scoped(Anchor::new("org", "o1")),
        role_grant("e", "editors", "project.edit"),
    ];
    let assign = Mutation::AssignRole {
        subject: Subject::user("ana"),
        role: RoleAssignment::in_scope("editors", Anchor::new("org", "o2")),
    };
    assert_eq!(
        invariant_of(governance.apply(&engine, &Subject::user("lead"), &grants, &assign, None)),
        "no_escalation"
    );
}

#[test]
fn no_escalation_bypass_exempts_its_holder() {
    let engine = engine();
    let bypass = Bypass::new("project.manage", project());
    let governance = Governance::new().with(NoEscalation::new().bypass(bypass));
    let grants = vec![
        user_grant("m", "root", "project.manage"),
        user_grant("l", "lead", "project.view"),
    ];
    let edit = Mutation::Add(user_grant("b", "ana", "project.edit"));

    governance
        .apply(&engine, &Subject::user("root"), &grants, &edit, None)
        .expect("bypass holder");
    assert_eq!(
        invariant_of(governance.apply(&engine, &Subject::user("lead"), &grants, &edit, None)),
        "no_escalation"
    );
}

fn lockout_governance(boss: Subject, spare: Subject) -> Governance {
    Governance::new().with(
        NoLockout::new(["project.manage"], vec![boss, spare.clone()], project()).with_reserve(role("admin"), [spare]),
    )
}

#[test]
fn no_lockout_proposes_the_reserve_and_the_proposal_passes_once_applied() {
    let engine = engine();
    let grants = vec![role_grant("a", "admin", "project.manage")];
    let boss = Subject::user("boss").with_role("admin");
    let spare = Subject::user("spare");
    let actor = Subject::user("actor");
    let revoke = Mutation::RevokeRole {
        subject: boss.clone(),
        role: role("admin"),
    };

    let violations = lockout_governance(boss.clone(), spare.clone())
        .apply(&engine, &actor, &grants, &revoke, None)
        .expect_err("refused");
    assert_eq!(violations[0].invariant, "no_lockout");
    let suggestion = *violations[0].suggestion.clone().expect("suggestion");
    assert_eq!(
        suggestion,
        Suggestion::AssignRole {
            subject_id: "spare".into(),
            role: role("admin")
        }
    );

    // Nothing was applied: the caller sends the fix, reloads the members, and resends the refusal.
    let fix = suggestion.into_mutation(spare.clone());
    let promoted = fix.subject_after().expect("role change");
    lockout_governance(boss.clone(), spare.clone())
        .apply(&engine, &actor, &grants, &fix, None)
        .expect("the fix is an ordinary change");
    lockout_governance(boss, promoted)
        .apply(&engine, &actor, &grants, &revoke, None)
        .expect("resend passes");
}

#[test]
fn no_lockout_without_reserve_still_refuses_without_suggestion() {
    let engine = engine();
    let grants = vec![role_grant("a", "admin", "project.manage")];
    let boss = Subject::user("boss").with_role("admin");
    let governance = Governance::new().with(NoLockout::new(["project.manage"], vec![boss.clone()], project()));
    let revoke = Mutation::RevokeRole {
        subject: boss,
        role: role("admin"),
    };
    let violations = governance
        .apply(&engine, &Subject::user("actor"), &grants, &revoke, None)
        .expect_err("refused");
    assert!(violations[0].suggestion.is_none());
}

#[test]
fn audit_records_the_refusal_with_the_suggestion() {
    use std::sync::Arc;
    use themis::{AuditLevel, Auditor, MemoryAuditLog};

    let engine = engine();
    let grants = vec![role_grant("a", "admin", "project.manage")];
    let boss = Subject::user("boss").with_role("admin");
    let spare = Subject::user("spare");
    let log = Arc::new(MemoryAuditLog::new());
    let governance =
        lockout_governance(boss.clone(), spare).audited(Arc::new(Auditor::new(AuditLevel::Standard, log.clone())));
    let revoke = Mutation::RevokeRole {
        subject: boss,
        role: role("admin"),
    };
    governance
        .apply(&engine, &Subject::user("actor"), &grants, &revoke, None)
        .expect_err("refused");
    let records = log.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].suggestions.len(), 1);
}

fn suggestion_of(governance: &Governance, actor: &Subject, boss: &Subject) -> Option<Suggestion> {
    let grants = vec![role_grant("a", "admin", "project.manage")];
    let revoke = Mutation::RevokeRole {
        subject: boss.clone(),
        role: role("admin"),
    };
    let violations = governance
        .apply(&engine(), actor, &grants, &revoke, None)
        .expect_err("refused");
    assert_eq!(violations[0].invariant, "no_lockout");
    violations[0].suggestion.as_deref().cloned()
}

#[test]
fn no_lockout_does_not_suggest_a_reserve_outside_the_members() {
    let boss = Subject::user("boss").with_role("admin");
    let outsider = Subject::user("outsider");
    let governance = Governance::new().with(
        NoLockout::new(["project.manage"], vec![boss.clone()], project()).with_reserve(role("admin"), [outsider]),
    );
    // The invariant only counts its members, so promoting an outsider would not lift the refusal.
    assert_eq!(suggestion_of(&governance, &Subject::user("actor"), &boss), None);
}

#[test]
fn no_lockout_never_suggests_the_actor_and_picks_another_reserve() {
    let boss = Subject::user("boss").with_role("admin");
    let spare = Subject::user("spare");
    let other = Subject::user("other");
    let build = |reserve: Vec<Subject>| {
        Governance::new().with(NoSelfManagement).with(
            NoLockout::new(
                ["project.manage"],
                vec![boss.clone(), spare.clone(), other.clone()],
                project(),
            )
            .with_reserve(role("admin"), reserve),
        )
    };
    // The only reserve is the actor: assigning the role to themselves would be refused.
    assert_eq!(suggestion_of(&build(vec![spare.clone()]), &spare, &boss), None);
    // With a second reserve, the suggestion goes to the one who is not the actor.
    assert_eq!(
        suggestion_of(&build(vec![spare.clone(), other.clone()]), &spare, &boss),
        Some(Suggestion::AssignRole {
            subject_id: "other".into(),
            role: role("admin")
        })
    );
}

#[test]
fn no_lockout_drops_a_suggestion_that_another_invariant_would_refuse() {
    let boss = Subject::user("boss").with_role("admin");
    let spare = Subject::user("spare");
    let governance = Governance::new()
        .with(Forbid::new(SubjectMatcher::user("spare"), ["project.manage"]))
        .with(
            NoLockout::new(["project.manage"], vec![boss.clone(), spare.clone()], project())
                .with_reserve(role("admin"), [spare]),
        );
    // The role carries `project.manage`, which `Forbid` keeps from `spare`: the fix would be refused.
    assert_eq!(suggestion_of(&governance, &Subject::user("actor"), &boss), None);
}

#[test]
fn no_lockout_accounts_for_the_change_when_it_touches_the_reserve() {
    // The refused change revokes the admin role of the very reserve subject; promoting them again
    // is not a fix, and the suggestion has to see that.
    let boss = Subject::user("boss").with_role("admin");
    let spare = Subject::user("spare").with_role("admin");
    let governance = Governance::new().with(
        NoLockout::new(["project.manage"], vec![spare.clone()], project())
            .with_reserve(role("admin"), [spare.clone(), boss]),
    );
    let grants = vec![role_grant("a", "admin", "project.manage")];
    let revoke = Mutation::RevokeRole {
        subject: spare,
        role: role("admin"),
    };
    let violations = governance
        .apply(&engine(), &Subject::user("actor"), &grants, &revoke, None)
        .expect_err("refused");
    assert!(violations[0].suggestion.is_none());
}

#[test]
fn the_suggestion_exposes_only_the_id_and_the_role() {
    use std::sync::Arc;
    use themis::{AuditLevel, Auditor, MemoryAuditLog};

    let boss = Subject::user("boss").with_role("admin");
    let spare = Subject::user("spare")
        .with_principal("emergency")
        .with_attr("phone", "555-0100");
    let log = Arc::new(MemoryAuditLog::new());
    let governance =
        lockout_governance(boss.clone(), spare).audited(Arc::new(Auditor::new(AuditLevel::Standard, log.clone())));
    let grants = vec![role_grant("a", "admin", "project.manage")];
    let revoke = Mutation::RevokeRole {
        subject: boss,
        role: role("admin"),
    };
    let violations = governance
        .apply(&engine(), &Subject::user("actor"), &grants, &revoke, None)
        .expect_err("refused");
    let shown = serde_json::to_string(&violations).expect("json");
    let recorded = serde_json::to_string(&log.records()).expect("json");
    for text in [shown, recorded] {
        assert!(text.contains("spare"), "{text}");
        assert!(!text.contains("emergency") && !text.contains("555-0100"), "{text}");
    }
}
