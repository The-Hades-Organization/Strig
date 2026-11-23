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
    result
        .expect_err("refused")
        .into_iter()
        .map(|v| v.invariant)
        .collect()
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
        let result = governance.at(now).apply(&engine, &admin(), &current, &new_grant(), None);
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
    assert!(governance.apply(&engine, &admin(), &current, &new_grant(), None).is_ok());
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
    let actor = Subject::user("admin").with_assignment(RoleAssignment::in_scope("admin", org()).valid_between(FROM, UNTIL));
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
