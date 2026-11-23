//! Governance and validity windows: the instant comes in explicitly, and what is outside its
//! window does not exist for the change.

mod support;

use support::*;
use themis::{
    CatalogConformance, Governance, Grant, Mutation, NoSelfManagement, RequirePermission, RoleAssignment, Subject,
    Violation,
};

const FROM: u64 = 1_000;
const UNTIL: u64 = 2_000;

fn new_grant() -> Mutation {
    Mutation::Add(role_grant("new", "member", "project.view", true, at_org()))
}

fn governance() -> Governance {
    Governance::new()
        .with(CatalogConformance)
        .with(RequirePermission::new("org.roles.edit", project()))
        .with(NoSelfManagement)
}

fn invariants(result: Result<Vec<Grant>, Vec<Violation>>) -> Vec<String> {
    result.expect_err("refused").into_iter().map(|v| v.invariant).collect()
}

fn admin() -> Subject {
    Subject::user("admin").with_role_in("admin", org())
}

#[test]
fn a_windowed_actor_grant_counts_only_at_the_instant_inside_the_window() {
    let current = vec![role_grant("admin-manage", "admin", "org.manage", true, at_org()).valid_between(FROM, UNTIL)];
    let (engine, governance) = (engine(), governance());

    for now in [FROM, UNTIL - 1] {
        let applied = governance
            .at(now)
            .apply(&engine, &admin(), &current, &new_grant(), None)
            .expect("inside the window");
        assert_eq!(applied.len(), 2);
    }
    for now in [FROM - 1, UNTIL] {
        let result = governance
            .at(now)
            .apply(&engine, &admin(), &current, &new_grant(), None);
        assert_eq!(invariants(result), ["require_permission"], "at {now}");
    }
}

#[test]
fn without_an_instant_a_windowed_allow_fails_closed() {
    let current = vec![role_grant("admin-manage", "admin", "org.manage", true, at_org()).valid_between(FROM, UNTIL)];
    let result = governance().apply(&engine(), &admin(), &current, &new_grant(), None);
    assert_eq!(invariants(result), ["require_permission"]);
}

#[test]
fn a_grant_without_a_window_does_not_need_the_instant() {
    let current = vec![role_grant("admin-manage", "admin", "org.manage", true, at_org())];
    let (engine, governance) = (engine(), governance());
    assert!(
        governance
            .apply(&engine, &admin(), &current, &new_grant(), None)
            .is_ok()
    );
    assert!(
        governance
            .at(UNTIL * 10)
            .apply(&engine, &admin(), &current, &new_grant(), None)
            .is_ok()
    );
}

#[test]
fn a_windowed_actor_role_counts_only_at_the_instant_inside_the_window() {
    let current = vec![role_grant("admin-manage", "admin", "org.manage", true, at_org())];
    let actor =
        Subject::user("admin").with_assignment(RoleAssignment::in_scope("admin", org()).valid_between(FROM, UNTIL));
    let (engine, governance) = (engine(), governance());

    assert!(
        governance
            .at(FROM)
            .apply(&engine, &actor, &current, &new_grant(), None)
            .is_ok()
    );
    for now in [FROM - 1, UNTIL] {
        let result = governance.at(now).apply(&engine, &actor, &current, &new_grant(), None);
        assert_eq!(invariants(result), ["require_permission"], "at {now}");
    }
    let result = governance.apply(&engine, &actor, &current, &new_grant(), None);
    assert_eq!(invariants(result), ["require_permission"]);
}

fn assignment_governance() -> (themis::Engine, Governance) {
    (engine(), governance())
}

fn base() -> Vec<Grant> {
    vec![
        role_grant("admin-manage", "admin", "org.manage", true, at_org()),
        role_grant("member-view", "member", "project.view", true, at_org()),
    ]
}

#[test]
fn assigning_a_role_with_an_inverted_window_is_refused_and_removing_it_is_cleanup() {
    let (engine, governance) = assignment_governance();
    let inverted = RoleAssignment::in_scope("member", org()).valid_between(UNTIL, FROM);
    let assign = Mutation::AssignRole {
        subject: Subject::user("u1"),
        role: inverted.clone(),
    };
    for result in [
        governance.apply(&engine, &admin(), &base(), &assign, None),
        governance.at(FROM).apply(&engine, &admin(), &base(), &assign, None),
    ] {
        let violations = result.expect_err("refused");
        assert_eq!(violations[0].invariant, "mutation");
        assert!(
            violations[0].message.contains("empty validity window"),
            "{}",
            violations[0]
        );
    }

    let stored = Subject::user("u1").with_assignment(inverted.clone());
    let revoke = Mutation::RevokeRole {
        subject: stored,
        role: inverted,
    };
    governance
        .apply(&engine, &admin(), &base(), &revoke, None)
        .expect("a stored malformed assignment can still be removed");
}

#[test]
fn self_management_counts_a_role_until_it_ends_and_one_that_starts_later() {
    let engine = engine();
    let governance = Governance::new().with(NoSelfManagement);
    let actor = |role: RoleAssignment| Subject::user("ana").with_assignment(role);
    let on_member = Mutation::Add(role_grant("new", "member", "project.edit", true, at_org()));

    let windowed = actor(RoleAssignment::new("member").valid_between(FROM, UNTIL));
    for now in [FROM - 1, FROM, UNTIL - 1] {
        let result = governance.at(now).apply(&engine, &windowed, &base(), &on_member, None);
        assert_eq!(invariants(result), ["no_self_management"], "at {now}");
    }
    governance
        .at(UNTIL)
        .apply(&engine, &windowed, &base(), &on_member, None)
        .expect("the role ended: it is not the actor's any more");
    // Nothing is known to have ended without an instant: the guard keeps counting the role.
    let result = governance.apply(&engine, &windowed, &base(), &on_member, None);
    assert_eq!(invariants(result), ["no_self_management"]);

    let malformed = actor(RoleAssignment::new("member").valid_between(UNTIL, FROM));
    governance
        .at(FROM)
        .apply(&engine, &malformed, &base(), &on_member, None)
        .expect("a malformed window never holds anything");
}
