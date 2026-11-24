//! RBAC com herança, ABAC com condição e ReBAC no mesmo motor.

mod support;

use strig::{
    Anchor, Attributes, Condition, ConditionError, ConditionRegistry, Context, DenyOverrides, Engine, Grant,
    InMemoryTuples, ObjectRef, Operand, RelationSchema, Request, Resource, Rewrite, RoleGraph, Subject, SubjectMatcher,
    TargetSelector, Tuple, Value,
};
use support::*;

#[test]
fn rbac_role_inheritance() {
    let roles = RoleGraph::builder().inherit("maintainer", "member").build().unwrap();
    let engine = Engine::builder(catalog()).roles(roles).build().unwrap();
    let grants = vec![role_grant("g1", "member", "project.view", true, at_org())];
    let maintainer = Subject::user("u1").with_role_in("maintainer", org());
    assert!(engine.check(
        &Context::new(&grants),
        &Request::new(&maintainer, "project.view", &project())
    ));
}

#[test]
fn abac_condition_on_attributes_and_environment() {
    let registry = ConditionRegistry::new().register("business_hours", |args| match args {
        [Value::Int(hour)] => Ok((8..18).contains(hour)),
        _ => Err(ConditionError::Function("business_hours(int)".into())),
    });
    let engine = Engine::builder(catalog()).conditions(registry).build().unwrap();
    let grant = role_grant("g1", "member", "document.export", true, at_org()).when(Condition::all([
        Condition::eq(Operand::attr("subject.plan"), Operand::lit("pro")),
        Condition::call("business_hours", [Operand::attr("env.hour")]),
    ]));
    engine.validate_grant(&grant).unwrap();
    let grants = vec![grant];

    let pro = Subject::user("u1")
        .with_role_in("member", org())
        .with_attr("plan", "pro");
    let free = Subject::user("u2")
        .with_role_in("member", org())
        .with_attr("plan", "free");
    let invoice = document("d1", "invoice");
    let mut env = Attributes::new();

    env.insert("hour".into(), Value::Int(10));
    let ctx = Context::new(&grants).with_env(&env);
    assert!(engine.check(&ctx, &Request::new(&pro, "document.invoice.export", &invoice)));
    assert!(!engine.check(&ctx, &Request::new(&free, "document.invoice.export", &invoice)));

    env.insert("hour".into(), Value::Int(22));
    let ctx = Context::new(&grants).with_env(&env);
    assert!(!engine.check(&ctx, &Request::new(&pro, "document.invoice.export", &invoice)));
}

#[test]
fn abac_error_never_opens_access_but_still_denies() {
    let engine = Engine::builder(catalog()).build().unwrap();
    let missing = Condition::eq(Operand::attr("subject.department"), Operand::lit("eng"));
    let grants = vec![
        role_grant("allow", "member", "project.view", true, at_org()),
        role_grant(
            "deny",
            "member",
            "project.view",
            false,
            TargetSelector::exact("project", PROJECT),
        )
        .when(missing.clone()),
    ];
    let subject = Subject::user("u1").with_role_in("member", org());
    let decision = engine.decide(
        &Context::new(&grants),
        &Request::new(&subject, "project.view", &project()),
    );
    assert!(!decision.is_allowed());
    assert_eq!(decision.warnings.len(), 1);

    let grants = vec![role_grant("allow", "member", "project.view", true, at_org()).when(missing)];
    assert!(!engine.check(
        &Context::new(&grants),
        &Request::new(&subject, "project.view", &project())
    ));
}

fn rebac_engine() -> Engine {
    let schema = RelationSchema::new()
        .relation(
            "project",
            "editor",
            Rewrite::union([Rewrite::This, Rewrite::computed("owner")]),
        )
        .relation(
            "project",
            "viewer",
            Rewrite::union([
                Rewrite::This,
                Rewrite::computed("editor"),
                Rewrite::from_parent("parent", "member"),
            ]),
        );
    Engine::builder(catalog()).relations(schema).build().unwrap()
}

fn tuples() -> InMemoryTuples {
    let p = ObjectRef::new("project", PROJECT);
    [
        Tuple::new(p.clone(), "owner", ObjectRef::new("user", "alice")),
        Tuple::new(p.clone(), "editor", ObjectRef::new("user", "bob")),
        Tuple::new(p, "parent", ObjectRef::new("org", ORG)),
        Tuple::new(ObjectRef::new("org", ORG), "member", ObjectRef::new("user", "carol")),
    ]
    .into_iter()
    .collect()
}

fn relation_grants() -> Vec<Grant> {
    vec![
        Grant::allow(
            "edit",
            SubjectMatcher::relation("editor"),
            "project.edit",
            TargetSelector::kind("project"),
        ),
        Grant::allow(
            "view",
            SubjectMatcher::relation("viewer"),
            "project.view",
            TargetSelector::kind("project"),
        ),
    ]
}

#[test]
fn rebac_relations_drive_grants() {
    let engine = rebac_engine();
    let store = tuples();
    let grants = relation_grants();
    let ctx = Context::new(&grants).with_tuples(&store);
    let p = project();
    let check = |user: &str, key: &str| engine.check(&ctx, &Request::new(&Subject::user(user), key, &p));

    assert!(check("alice", "project.edit"));
    assert!(check("bob", "project.edit"));
    assert!(!check("carol", "project.edit"));
    assert!(check("carol", "project.view"));
    assert!(check("carol", "document.report.view"));
    assert!(!check("dave", "project.view"));
}

#[test]
fn rebac_without_store_fails_closed() {
    let engine = rebac_engine();
    let grants = relation_grants();
    let decision = engine.decide(
        &Context::new(&grants),
        &Request::new(&Subject::user("alice"), "project.edit", &project()),
    );
    assert!(!decision.is_allowed());
    assert!(!decision.warnings.is_empty());
}

#[test]
fn strategy_is_pluggable() {
    let engine = Engine::builder(catalog()).strategy(DenyOverrides).build().unwrap();
    let grants = vec![
        role_grant("g1", "member", "document.view", false, at_org()),
        role_grant(
            "g2",
            "member",
            "document.report.view",
            true,
            TargetSelector::exact("doc_type", "report"),
        ),
    ];
    let subject = Subject::user("u1").with_role_in("member", org());
    assert!(!engine.check(
        &Context::new(&grants),
        &Request::new(&subject, "document.report.view", &document("d1", "report"))
    ));
}

#[test]
fn override_exception() {
    let engine = Engine::builder(catalog())
        .override_except(strig::PermissionHolder::new("org.manage"), ["project.delete"])
        .build()
        .unwrap();
    let grants = vec![role_grant("g1", "admin", "org.manage", true, at_org())];
    let admin = Subject::user("u2").with_role_in("admin", org());
    let ctx = Context::new(&grants);
    assert!(engine.check(&ctx, &Request::new(&admin, "project.edit", &project())));
    assert!(!engine.check(&ctx, &Request::new(&admin, "project.delete", &project())));
}

#[test]
fn unknown_permission_is_denied() {
    let engine = Engine::builder(catalog()).build().unwrap();
    let grants = vec![Grant::allow(
        "g",
        SubjectMatcher::Any,
        "project.view",
        TargetSelector::global(),
    )];
    let decision = engine.decide(
        &Context::new(&grants),
        &Request::new(&Subject::user("u"), "project.typo", &Resource::global()),
    );
    assert_eq!(decision.reason, strig::Reason::UnknownPermission);
}

#[test]
fn grant_json_shape_is_stable() {
    let grant = Grant::allow(
        "g1",
        SubjectMatcher::role("member"),
        "project.view",
        TargetSelector::exact("org", ORG),
    )
    .scoped(Anchor::new("org", ORG));
    let json = serde_json::to_value(&grant).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "id": "g1",
            "subject": {"kind": "role", "id": "member"},
            "permission": "project.view",
            "target": {"kind": "org", "id": ORG},
            "effect": "allow",
            "scope": {"kind": "org", "id": ORG}
        })
    );
}
