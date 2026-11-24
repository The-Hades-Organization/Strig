//! `NoEscalation`: conditions, implied permissions and lifting a `deny` count as handing out access.

use strig::{
    Catalog, Condition, Engine, Governance, Grant, Mutation, NoEscalation, Operand, PermissionDef, RoleAssignment,
    Subject, SubjectMatcher, TargetSelector, Violation,
};

fn engine() -> Engine {
    let catalog = Catalog::builder()
        .target_kind("project")
        .permission(PermissionDef::new("project.view").targets(["project"]))
        .permission(PermissionDef::new("project.edit").targets(["project"]))
        .permission(PermissionDef::new("project.manage").targets(["project"]))
        .permission(
            PermissionDef::new("project.delete")
                .targets(["project"])
                .implied_by(["project.manage"]),
        )
        .build()
        .expect("catalog");
    Engine::builder(catalog).build().expect("engine")
}

fn on_projects() -> TargetSelector {
    TargetSelector::kind("project")
}

fn allow(id: &str, user: &str, key: &str) -> Grant {
    Grant::allow(id, SubjectMatcher::user(user), key, on_projects())
}

fn deny(id: &str, user: &str, key: &str) -> Grant {
    Grant::deny(id, SubjectMatcher::user(user), key, on_projects())
}

fn role(name: &str) -> RoleAssignment {
    RoleAssignment::new(name)
}

fn in_finance() -> Condition {
    Condition::eq(Operand::attr("subject.dept"), Operand::lit("fin"))
}

fn refused(result: Result<Vec<Grant>, Vec<Violation>>) -> String {
    result.expect_err("refused").remove(0).invariant
}

fn governance() -> Governance {
    Governance::new().with(NoEscalation::new())
}

fn lead() -> Subject {
    Subject::user("lead").with_attr("dept", "fin")
}

#[test]
fn a_conditional_holder_cannot_hand_out_the_permission_without_the_condition() {
    let engine = engine();
    let grants = vec![allow("l", "lead", "project.edit").when(in_finance())];

    let bare = Mutation::Add(allow("a", "ana", "project.edit"));
    assert_eq!(
        refused(governance().apply(&engine, &lead(), &grants, &bare, None)),
        "no_escalation"
    );

    let other = Condition::eq(Operand::attr("subject.dept"), Operand::lit("hr"));
    let unrelated = Mutation::Add(allow("a", "ana", "project.edit").when(other.clone()));
    assert_eq!(
        refused(governance().apply(&engine, &lead(), &grants, &unrelated, None)),
        "no_escalation"
    );

    let same = Mutation::Add(allow("a", "ana", "project.edit").when(in_finance()));
    governance()
        .apply(&engine, &lead(), &grants, &same, None)
        .expect("same condition");

    let narrower = Mutation::Add(allow("a", "ana", "project.edit").when(Condition::all([other, in_finance()])));
    governance()
        .apply(&engine, &lead(), &grants, &narrower, None)
        .expect("the condition is among the terms of an all");
}

#[test]
fn an_unconditional_holder_hands_out_with_or_without_condition() {
    let engine = engine();
    let grants = vec![
        allow("l", "lead", "project.edit").when(in_finance()),
        allow("u", "lead", "project.edit"),
    ];
    let bare = Mutation::Add(allow("a", "ana", "project.edit"));
    governance()
        .apply(&engine, &lead(), &grants, &bare, None)
        .expect("one unconditional grant is enough");
}

#[test]
fn a_conditional_role_must_keep_its_condition_when_the_actor_is_conditional() {
    let engine = engine();
    let grants = vec![
        allow("l", "lead", "project.edit").when(in_finance()),
        Grant::allow("r", SubjectMatcher::role("editors"), "project.edit", on_projects()),
    ];
    let assign = Mutation::AssignRole {
        subject: Subject::user("ana"),
        role: role("editors"),
    };
    assert_eq!(
        refused(governance().apply(&engine, &lead(), &grants, &assign, None)),
        "no_escalation"
    );
}

#[test]
fn every_implied_permission_must_be_held_not_only_the_one_named() {
    let engine = engine();
    // `delete` is implied by `manage`; the lead holds `manage` but has a `deny` on `delete`.
    let grants = vec![
        allow("m", "lead", "project.manage"),
        deny("d", "lead", "project.delete"),
    ];
    let lead = Subject::user("lead");
    let manage = Mutation::Add(allow("a", "ana", "project.manage"));
    assert_eq!(
        refused(governance().apply(&engine, &lead, &grants, &manage, None)),
        "no_escalation"
    );

    let clean = vec![allow("m", "lead", "project.manage")];
    governance()
        .apply(&engine, &lead, &clean, &manage, None)
        .expect("holds manage and what it implies");
}

#[test]
fn lifting_a_deny_requires_holding_what_it_blocked() {
    let engine = engine();
    let grants = vec![allow("a", "bob", "project.delete"), deny("d", "bob", "project.delete")];
    let lift = Mutation::Remove { id: "d".into() };

    let nobody = Subject::user("nobody");
    assert_eq!(
        refused(governance().apply(&engine, &nobody, &grants, &lift, None)),
        "no_escalation"
    );

    let mut with_delete = grants.clone();
    with_delete.push(allow("x", "boss", "project.delete"));
    governance()
        .apply(&engine, &Subject::user("boss"), &with_delete, &lift, None)
        .expect("the actor holds delete");

    let allow_removed = Mutation::Remove { id: "a".into() };
    governance()
        .apply(&engine, &nobody, &grants, &allow_removed, None)
        .expect("removing an allow narrows access");
}

#[test]
fn lifting_a_deny_covers_the_permissions_it_implied() {
    let engine = engine();
    // The deny on `manage` also blocked `delete` (implied by `manage`).
    let grants = vec![deny("d", "bob", "project.manage"), allow("x", "boss", "project.manage")];
    let lift = Mutation::Remove { id: "d".into() };
    // `boss` holds manage, hence delete: passes. Dropping manage for delete only fails.
    governance()
        .apply(&engine, &Subject::user("boss"), &grants, &lift, None)
        .expect("holds manage");
    let only_delete = vec![deny("d", "bob", "project.manage"), allow("x", "boss", "project.delete")];
    assert_eq!(
        refused(governance().apply(&engine, &Subject::user("boss"), &only_delete, &lift, None)),
        "no_escalation"
    );
}

#[test]
fn revoking_a_role_that_carries_a_deny_requires_holding_what_it_blocked() {
    let engine = engine();
    let grants = vec![
        Grant::deny("d", SubjectMatcher::role("restricted"), "project.delete", on_projects()),
        allow("x", "boss", "project.delete"),
    ];
    let bob = Subject::user("bob").with_role("restricted");
    let revoke = Mutation::RevokeRole {
        subject: bob,
        role: role("restricted"),
    };
    assert_eq!(
        refused(governance().apply(&engine, &Subject::user("nobody"), &grants, &revoke, None)),
        "no_escalation"
    );
    governance()
        .apply(&engine, &Subject::user("boss"), &grants, &revoke, None)
        .expect("the actor holds delete");
}
