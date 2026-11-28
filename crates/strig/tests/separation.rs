//! Separação de funções: estática (papel direto, herança, grant, elevação) e dinâmica.

use strig::{
    ActionConflict, Anchor, Catalog, Context, Effect, Engine, ExclusiveKind, Governance, Grant, Mutation,
    MutualExclusion, PermissionDef, Reason, Request, Resource, RoleAssignment, RoleGraph, SeparationOfDuties, Subject,
    SubjectMatcher, TargetSelector, Value,
};

fn catalog() -> Catalog {
    Catalog::builder()
        .target_kinds(["org", "payment"])
        .permission(PermissionDef::new("payment.create").targets(["payment"]))
        .permission(PermissionDef::new("payment.approve").targets(["payment"]))
        .permission(PermissionDef::new("payment.view").targets(["payment"]))
        .mutually_exclusive(
            MutualExclusion::new("payment_duties", ExclusiveKind::Roles, ["maker", "checker"]).per_anchor("org"),
        )
        .mutually_exclusive(MutualExclusion::new(
            "global_roles",
            ExclusiveKind::Roles,
            ["auditor", "treasurer"],
        ))
        .mutually_exclusive(MutualExclusion::new(
            "create_or_approve",
            ExclusiveKind::Permissions,
            ["payment.create", "payment.approve"],
        ))
        .conflicting_actions(ActionConflict::new(
            "four_eyes",
            ["payment.create"],
            ["payment.approve"],
        ))
        .build()
        .expect("catalog")
}

fn roles() -> RoleGraph {
    RoleGraph::builder().inherit("lead", "checker").build().expect("roles")
}

fn engine() -> Engine {
    Engine::builder(catalog()).roles(roles()).build().expect("engine")
}

fn governance() -> Governance {
    Governance::new().with(SeparationOfDuties::new())
}

fn org(id: &str) -> Anchor {
    Anchor::new("org", id)
}

fn assign(subject: &Subject, role: &str, scope: Option<Anchor>) -> Mutation {
    Mutation::AssignRole {
        subject: subject.clone(),
        role: RoleAssignment {
            role: role.to_string(),
            scope,
            valid_from: None,
            valid_until: None,
        },
    }
}

fn apply(subject: &Subject, grants: &[Grant], mutation: &Mutation) -> Result<Vec<Grant>, Vec<strig::Violation>> {
    governance().apply(&engine(), subject, grants, mutation, None)
}

fn message(result: Result<Vec<Grant>, Vec<strig::Violation>>) -> String {
    let violations = result.expect_err("a violation");
    assert_eq!(violations[0].invariant, "separation_of_duties");
    violations[0].message.clone()
}

fn admin() -> Subject {
    Subject::user("admin")
}

#[test]
fn a_direct_role_that_completes_a_set_is_refused_naming_the_set_and_both_sides() {
    let ana = Subject::user("ana").with_role_in("maker", org("o1"));
    let text = message(apply(&admin(), &[], &assign(&ana, "checker", Some(org("o1")))));
    assert!(text.contains("payment_duties"), "{text}");
    assert!(text.contains("'maker'") && text.contains("'checker'"), "{text}");
    assert!(text.contains("ana"), "{text}");
}

#[test]
fn a_member_of_another_set_or_alone_is_accepted() {
    let ana = Subject::user("ana").with_role_in("maker", org("o1"));
    assert!(apply(&admin(), &[], &assign(&ana, "viewer", Some(org("o1")))).is_ok());
    assert!(
        apply(
            &admin(),
            &[],
            &assign(&Subject::user("bia"), "checker", Some(org("o1")))
        )
        .is_ok()
    );
}

#[test]
fn a_set_per_anchor_clashes_only_inside_the_same_anchor() {
    let ana = Subject::user("ana").with_role_in("maker", org("o1"));
    assert!(apply(&admin(), &[], &assign(&ana, "checker", Some(org("o2")))).is_ok());
    assert!(apply(&admin(), &[], &assign(&ana, "checker", Some(org("o1")))).is_err());
}

#[test]
fn an_unscoped_holding_clashes_with_a_scoped_one() {
    let ana = Subject::user("ana").with_role_in("maker", org("o1"));
    assert!(apply(&admin(), &[], &assign(&ana, "checker", None)).is_err());
}

#[test]
fn a_global_set_clashes_wherever_the_members_are_held() {
    let ana = Subject::user("ana").with_role_in("auditor", org("o1"));
    let text = message(apply(&admin(), &[], &assign(&ana, "treasurer", Some(org("o2")))));
    assert!(text.contains("global_roles"), "{text}");
    assert!(text.contains("global"), "{text}");
}

#[test]
fn a_role_that_inherits_a_member_counts_as_that_member() {
    let ana = Subject::user("ana").with_role_in("maker", org("o1"));
    let text = message(apply(&admin(), &[], &assign(&ana, "lead", Some(org("o1")))));
    assert!(text.contains("payment_duties"), "{text}");
    assert!(text.contains("'checker'"), "{text}");
}

#[test]
fn a_clash_that_was_already_there_does_not_block_an_unrelated_change() {
    let ana = Subject::user("ana")
        .with_role_in("maker", org("o1"))
        .with_role_in("checker", org("o1"));
    assert!(apply(&admin(), &[], &assign(&ana, "viewer", Some(org("o1")))).is_ok());
}

#[test]
fn revoking_a_role_never_creates_a_clash() {
    let ana = Subject::user("ana")
        .with_role_in("maker", org("o1"))
        .with_role_in("checker", org("o1"));
    let revoke = Mutation::RevokeRole {
        subject: ana.clone(),
        role: RoleAssignment {
            role: "maker".into(),
            scope: Some(org("o1")),
            valid_from: None,
            valid_until: None,
        },
    };
    assert!(apply(&admin(), &[], &revoke).is_ok());
}

fn allow(id: &str, user: &str, key: &str) -> Grant {
    Grant::allow(id, SubjectMatcher::user(user), key, TargetSelector::kind("payment"))
}

#[test]
fn a_grant_that_gives_the_second_permission_of_a_set_is_refused() {
    let held = vec![allow("g1", "ana", "payment.create")];
    let text = message(apply(
        &admin(),
        &held,
        &Mutation::Add(allow("g2", "ana", "payment.approve")),
    ));
    assert!(text.contains("create_or_approve"), "{text}");
    assert!(
        text.contains("payment.create") && text.contains("payment.approve"),
        "{text}"
    );
}

#[test]
fn a_grant_of_a_role_that_confers_the_second_permission_is_refused() {
    let held = vec![Grant::allow(
        "g1",
        SubjectMatcher::role("maker"),
        "payment.create",
        TargetSelector::kind("payment"),
    )];
    let ana = Subject::user("ana").with_role("maker");
    let add = Mutation::Add(Grant::allow(
        "g2",
        SubjectMatcher::role("maker"),
        "payment.approve",
        TargetSelector::kind("payment"),
    ));
    let result = governance().apply(&engine(), &ana, &held, &add, None);
    assert!(message(result).contains("create_or_approve"));
}

#[test]
fn a_denial_and_a_removal_are_never_refused() {
    let held = vec![
        allow("g1", "ana", "payment.create"),
        allow("g2", "ana", "payment.approve"),
    ];
    let deny = Mutation::Add(Grant::deny(
        "g3",
        SubjectMatcher::user("ana"),
        "payment.approve",
        TargetSelector::kind("payment"),
    ));
    assert!(apply(&admin(), &held, &deny).is_ok());
    assert!(apply(&admin(), &held, &Mutation::Remove { id: "g2".into() }).is_ok());
}

#[test]
fn a_temporary_elevation_that_completes_a_set_is_refused() {
    let held = vec![allow("g1", "ana", "payment.create")];
    let elevation = allow("elev", "ana", "payment.approve").valid_between(1_000, 2_000);
    let result = governance()
        .at(1_500)
        .apply(&engine(), &admin(), &held, &Mutation::Add(elevation), None);
    assert!(message(result).contains("create_or_approve"));
}

#[test]
fn a_permission_set_with_a_deny_on_the_other_member_is_not_a_clash() {
    let held = vec![
        allow("g1", "ana", "payment.create"),
        Grant::deny(
            "d1",
            SubjectMatcher::user("ana"),
            "payment.approve",
            TargetSelector::kind("payment"),
        ),
    ];
    let again = allow("g3", "ana", "payment.view");
    assert!(apply(&admin(), &held, &Mutation::Add(again)).is_ok());
}

// ---- dynamic ---------------------------------------------------------------------------------

fn payment(history: &[&str]) -> Resource {
    let list: Vec<Value> = history.iter().map(|h| Value::from(*h)).collect();
    Resource::new("payment", "p1")
        .within("org", "o1")
        .with_attr("history", Value::List(list))
}

fn approver_grants() -> Vec<Grant> {
    vec![Grant::allow(
        "approve",
        SubjectMatcher::role("checker"),
        "payment.approve",
        TargetSelector::kind("payment"),
    )]
}

fn decide(subject: &Subject, resource: &Resource) -> strig::Decision {
    let grants = approver_grants();
    engine().decide(
        &Context::new(&grants),
        &Request::new(subject, "payment.approve", resource),
    )
}

#[test]
fn who_did_the_first_action_on_the_resource_does_not_do_the_second() {
    let ana = Subject::user("ana").with_role("checker");
    let decision = decide(&ana, &payment(&["payment.create:ana"]));
    assert_eq!(decision.effect, Effect::Deny);
    assert!(matches!(&decision.reason, Reason::Override { name } if name == "separation:four_eyes"));
}

#[test]
fn someone_else_does_the_second_action() {
    let bia = Subject::user("bia").with_role("checker");
    assert_eq!(decide(&bia, &payment(&["payment.create:ana"])).effect, Effect::Allow);
}

#[test]
fn the_same_actor_on_another_resource_is_not_refused() {
    let ana = Subject::user("ana").with_role("checker");
    assert_eq!(decide(&ana, &payment(&[])).effect, Effect::Allow);
}

#[test]
fn a_malformed_history_fails_closed() {
    let ana = Subject::user("bia").with_role("checker");
    let bad = Resource::new("payment", "p1")
        .within("org", "o1")
        .with_attr("history", "oops");
    assert_eq!(decide(&ana, &bad).effect, Effect::Deny);
    let broken = payment(&["no-actor"]);
    assert_eq!(decide(&ana, &broken).effect, Effect::Deny);
}

#[test]
fn the_rule_only_touches_the_then_permissions() {
    let grants = vec![Grant::allow(
        "view",
        SubjectMatcher::role("checker"),
        "payment.view",
        TargetSelector::kind("payment"),
    )];
    let ana = Subject::user("ana").with_role("checker");
    let resource = payment(&["payment.create:ana"]);
    let decision = engine().decide(&Context::new(&grants), &Request::new(&ana, "payment.view", &resource));
    assert_eq!(decision.effect, Effect::Allow);
}

fn with_distinct_roles() -> Engine {
    let catalog = Catalog::builder()
        .target_kinds(["org", "payment"])
        .permission(PermissionDef::new("payment.create").targets(["payment"]))
        .permission(PermissionDef::new("payment.approve").targets(["payment"]))
        .conflicting_actions(ActionConflict::new("four_eyes", ["payment.create"], ["payment.approve"]).distinct_roles())
        .build()
        .unwrap();
    Engine::builder(catalog).roles(roles()).build().unwrap()
}

#[test]
fn distinct_roles_refuse_someone_with_a_role_the_author_acted_with() {
    let grants = approver_grants();
    let engine = with_distinct_roles();
    let bia = Subject::user("bia").with_role("checker");
    let by_checker = payment(&["payment.create:ana|checker"]);
    let denied = engine.decide(
        &Context::new(&grants),
        &Request::new(&bia, "payment.approve", &by_checker),
    );
    assert_eq!(denied.effect, Effect::Deny);
    let by_maker = payment(&["payment.create:ana|maker"]);
    let allowed = engine.decide(
        &Context::new(&grants),
        &Request::new(&bia, "payment.approve", &by_maker),
    );
    assert_eq!(allowed.effect, Effect::Allow);
}

#[test]
fn distinct_roles_without_the_authors_roles_fail_closed() {
    let grants = approver_grants();
    let engine = with_distinct_roles();
    let bia = Subject::user("bia").with_role("checker");
    let resource = payment(&["payment.create:ana"]);
    let decision = engine.decide(
        &Context::new(&grants),
        &Request::new(&bia, "payment.approve", &resource),
    );
    assert_eq!(decision.effect, Effect::Deny);
}

#[test]
fn the_history_may_come_from_env() {
    let grants = approver_grants();
    let ana = Subject::user("ana").with_role("checker");
    let resource = Resource::new("payment", "p1").within("org", "o1");
    let mut env = strig::Attributes::new();
    env.insert("history".into(), Value::List(vec![Value::from("payment.create:ana")]));
    let ctx = Context::new(&grants).with_env(&env);
    let decision = engine().decide(&ctx, &Request::new(&ana, "payment.approve", &resource));
    assert_eq!(decision.effect, Effect::Deny);
}
