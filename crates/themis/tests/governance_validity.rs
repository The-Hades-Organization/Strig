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

mod escalation_domain {
    use super::{FROM, UNTIL, invariants};
    use themis::{
        Catalog, Condition, Engine, Forbid, Governance, Grant, ManagementOnly, Mutation, NoEscalation, NoLockout,
        NonDelegable, Operand, PermissionDef, Prerequisites, Resource, RoleAssignment, Subject, SubjectMatcher,
        TargetSelector,
    };

    fn engine() -> Engine {
        let catalog = Catalog::builder()
            .target_kind("project")
            .permission(PermissionDef::new("project.view").targets(["project"]))
            .permission(
                PermissionDef::new("project.edit")
                    .targets(["project"])
                    .depends_on(["project.view"]),
            )
            .permission(PermissionDef::new("project.manage").targets(["project"]))
            .permission(
                PermissionDef::new("project.delete")
                    .targets(["project"])
                    .implied_by(["project.manage"]),
            )
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

    fn user_allow(id: &str, user: &str, key: &str) -> Grant {
        Grant::allow(id, SubjectMatcher::user(user), key, TargetSelector::kind("project"))
    }

    fn role_allow(id: &str, role: &str, key: &str) -> Grant {
        Grant::allow(id, SubjectMatcher::role(role), key, TargetSelector::kind("project"))
    }

    fn window(grant: Grant) -> Grant {
        grant.valid_between(FROM, UNTIL)
    }

    #[test]
    fn revoking_a_role_that_carries_a_deny_counts_only_while_the_assignment_has_not_ended() {
        let engine = engine();
        let governance = Governance::new().with(NoEscalation::new());
        let grants = vec![Grant::deny(
            "d",
            SubjectMatcher::role("restricted"),
            "project.delete",
            TargetSelector::kind("project"),
        )];
        let assignment = RoleAssignment::new("restricted").valid_between(FROM, UNTIL);
        let revoke = Mutation::RevokeRole {
            subject: Subject::user("bob").with_assignment(assignment.clone()),
            role: assignment,
        };
        let nobody = Subject::user("nobody");

        for now in [FROM - 1, FROM, UNTIL - 1] {
            let result = governance.at(now).apply(&engine, &nobody, &grants, &revoke, None);
            assert_eq!(invariants(result), ["no_escalation"], "at {now}");
        }
        let result = governance.apply(&engine, &nobody, &grants, &revoke, None);
        assert_eq!(invariants(result), ["no_escalation"], "no instant");
        governance
            .at(UNTIL)
            .apply(&engine, &nobody, &grants, &revoke, None)
            .expect("an ended assignment blocked nothing: removing it lifts nothing");
    }

    #[test]
    fn lifting_a_deny_that_has_ended_unlocks_nothing() {
        let engine = engine();
        let governance = Governance::new().with(NoEscalation::new());
        let grants = vec![window(Grant::deny(
            "d",
            SubjectMatcher::user("bob"),
            "project.delete",
            TargetSelector::kind("project"),
        ))];
        let lift = Mutation::Remove { id: "d".into() };
        let nobody = Subject::user("nobody");
        let result = governance.at(UNTIL - 1).apply(&engine, &nobody, &grants, &lift, None);
        assert_eq!(invariants(result), ["no_escalation"]);
        governance
            .at(UNTIL)
            .apply(&engine, &nobody, &grants, &lift, None)
            .expect("ended");
    }

    #[test]
    fn revoking_the_last_active_holder_is_a_lockout_even_if_an_ended_role_remains() {
        let engine = engine();
        let ana = Subject::user("ana").with_assignment(RoleAssignment::new("admin").valid_between(FROM, UNTIL));
        let bob = Subject::user("bob").with_role("admin");
        let governance = Governance::new().with(NoLockout::new(
            ["project.manage"],
            vec![ana.clone(), bob.clone()],
            project(),
        ));
        let grants = vec![role_allow("a", "admin", "project.manage")];
        let revoke_bob = Mutation::RevokeRole {
            subject: bob,
            role: RoleAssignment::new("admin"),
        };
        let revoke_ana = Mutation::RevokeRole {
            subject: ana.clone(),
            role: RoleAssignment::new("admin").valid_between(FROM, UNTIL),
        };
        let actor = Subject::user("root");

        governance
            .at(FROM)
            .apply(&engine, &actor, &grants, &revoke_bob, None)
            .expect("ana still holds it inside her window");
        let result = governance.at(UNTIL).apply(&engine, &actor, &grants, &revoke_bob, None);
        assert_eq!(invariants(result), ["no_lockout"]);
        governance
            .at(UNTIL)
            .apply(&engine, &actor, &grants, &revoke_ana, None)
            .expect("cleaning up an ended assignment changes nobody's access");
    }

    #[test]
    fn a_role_assignment_does_not_pass_forbidden_permission_it_will_carry() {
        let engine = engine();
        let governance = Governance::new().with(Forbid::new(SubjectMatcher::user("bob"), ["project.delete"]));
        let grants = vec![window(role_allow("g", "ops", "project.delete"))];
        let assign = Mutation::AssignRole {
            subject: Subject::user("bob"),
            role: RoleAssignment::new("ops"),
        };
        let actor = Subject::user("root");
        for now in [FROM - 1, FROM] {
            let result = governance.at(now).apply(&engine, &actor, &grants, &assign, None);
            assert_eq!(invariants(result), ["forbid"], "at {now}");
        }
        governance
            .at(UNTIL)
            .apply(&engine, &actor, &grants, &assign, None)
            .expect("the grant ended");
    }

    #[test]
    fn prerequisites_ignore_a_grant_outside_its_window() {
        let engine = engine();
        let governance = Governance::new().with(Prerequisites);
        let actor = Subject::user("boss");
        let add_edit = Mutation::Add(user_allow("e", "ana", "project.edit"));

        let expired_view = vec![window(user_allow("v", "ana", "project.view"))];
        let result = governance
            .at(UNTIL)
            .apply(&engine, &actor, &expired_view, &add_edit, None);
        assert_eq!(
            invariants(result),
            ["prerequisites"],
            "an ended prerequisite does not count"
        );
        governance
            .at(FROM)
            .apply(&engine, &actor, &expired_view, &add_edit, None)
            .expect("the prerequisite is in force");
        let result = governance.apply(&engine, &actor, &expired_view, &add_edit, None);
        assert_eq!(invariants(result), ["prerequisites"], "no instant: fails closed");

        // Removing a prerequisite that ended, or a dependent that ended, breaks nothing.
        let grants = vec![
            window(user_allow("v", "ana", "project.view")),
            user_allow("e", "ana", "project.edit"),
        ];
        governance
            .at(UNTIL)
            .apply(&engine, &actor, &grants, &Mutation::Remove { id: "v".into() }, None)
            .expect("the ended grant held nothing up");
        let result = governance
            .at(FROM)
            .apply(&engine, &actor, &grants, &Mutation::Remove { id: "v".into() }, None);
        assert_eq!(invariants(result), ["prerequisites"], "in force: edit depends on it");
    }

    #[test]
    fn a_role_outside_its_window_does_not_carry_its_prerequisite() {
        let engine = engine();
        let governance = Governance::new().with(Prerequisites);
        let actor = Subject::user("boss");
        let grants = vec![
            role_allow("v", "viewers", "project.view"),
            user_allow("e", "ana", "project.edit"),
        ];
        let assignment = RoleAssignment::new("viewers").valid_between(FROM, UNTIL);
        let ana = Subject::user("ana").with_assignment(assignment.clone());
        let revoke = Mutation::RevokeRole {
            subject: ana,
            role: assignment,
        };
        let result = governance.at(FROM).apply(&engine, &actor, &grants, &revoke, None);
        assert_eq!(invariants(result), ["prerequisites"], "ana would lose view");
        governance
            .at(UNTIL)
            .apply(&engine, &actor, &grants, &revoke, None)
            .expect("the role no longer gave her view");
    }

    #[test]
    fn non_delegable_and_management_only_read_what_a_role_carries_inside_its_window() {
        let engine = engine();
        let governance = Governance::new()
            .with(NonDelegable::new("project.manage"))
            .with(ManagementOnly::new(["boss"]));
        let grants = vec![
            window(role_allow("a", "ops", "project.admin")),
            window(role_allow("b", "ops", "project.billing")),
        ];
        let assign = Mutation::AssignRole {
            subject: Subject::user("ana"),
            role: RoleAssignment::new("ops"),
        };
        let actor = Subject::user("lead");
        for now in [FROM - 1, FROM] {
            let result = governance.at(now).apply(&engine, &actor, &grants, &assign, None);
            assert_eq!(invariants(result), ["non_delegable", "management_only"], "at {now}");
        }
        governance
            .at(UNTIL)
            .apply(&engine, &actor, &grants, &assign, None)
            .expect("the grants carried by the role ended");
    }

    #[test]
    fn escalation_condition_check_looks_only_at_the_grants_in_force() {
        let engine = engine();
        let governance = Governance::new().with(NoEscalation::new());
        let in_finance = Condition::eq(Operand::attr("subject.dept"), Operand::lit("fin"));
        let lead = Subject::user("lead").with_attr("dept", "fin");
        let grants = vec![
            window(user_allow("u", "lead", "project.manage")),
            user_allow("l", "lead", "project.manage").when(in_finance),
        ];
        let bare = Mutation::Add(user_allow("n", "ana", "project.manage"));

        governance
            .at(FROM)
            .apply(&engine, &lead, &grants, &bare, None)
            .expect("an unconditional grant is in force");
        for result in [
            governance.at(UNTIL).apply(&engine, &lead, &grants, &bare, None),
            governance.apply(&engine, &lead, &grants, &bare, None),
        ] {
            assert_eq!(invariants(result), ["no_escalation"]);
        }
    }
}
