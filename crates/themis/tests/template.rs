//! Role templates are detached copies: changing the template leaves what was materialized alone.

use themis::{
    Anchor, Catalog, Engine, Governance, Grant, NoEscalation, PermissionDef, RoleTemplate, Subject, SubjectMatcher,
    TargetSelector, TemplateGrant,
};

fn engine() -> Engine {
    let catalog = Catalog::builder()
        .target_kind("project")
        .broad_target("org")
        .permission(PermissionDef::new("project.view").targets(["project"]))
        .permission(PermissionDef::new("project.edit").targets(["project"]))
        .build()
        .expect("catalog");
    Engine::builder(catalog).build().expect("engine")
}

fn template(version: u32) -> RoleTemplate {
    RoleTemplate::new("reviewer", version)
        .grant(TemplateGrant::allow(
            "view",
            "project.view",
            TargetSelector::kind("project"),
        ))
        .grant(TemplateGrant::allow(
            "edit",
            "project.edit",
            TargetSelector::kind("project"),
        ))
}

#[test]
fn materialize_creates_new_grants_with_provenance() {
    let org = Anchor::new("org", "o1");
    let copy = template(3).materialize(SubjectMatcher::user("ana"), Some(org.clone()), "ana-reviewer");
    assert_eq!(copy.template, "reviewer");
    assert_eq!(copy.template_version, 3);
    assert_eq!(copy.meta.get("template"), Some(&"reviewer".into()));
    assert_eq!(copy.meta.get("template_version"), Some(&3u32.into()));
    let grants: Vec<&Grant> = copy
        .mutations
        .iter()
        .filter_map(|m| match m {
            themis::Mutation::Add(g) => Some(g),
            _ => None,
        })
        .collect();
    assert_eq!(grants.len(), 2);
    assert_eq!(grants[0].id, "ana-reviewer:view");
    assert_eq!(grants[0].scope, Some(org));
}

#[test]
fn changing_the_template_does_not_alter_what_was_materialized() {
    let engine = engine();
    let governance = Governance::new();
    let actor = Subject::user("boss");
    let copy = template(1).materialize(SubjectMatcher::user("ana"), None, "t1");
    let applied = copy.apply(&governance, &engine, &actor, &[], None).expect("applies");
    assert_eq!(applied.len(), 2);

    let mut changed = template(2);
    changed.grants.retain(|g| g.id == "view");
    changed.grants[0].permission = "project.edit".into();
    let second = changed.materialize(SubjectMatcher::user("bob"), None, "t2");

    // The first copy is untouched, and the new one is a separate set of grants.
    assert_eq!(applied.iter().filter(|g| g.id.starts_with("t1:")).count(), 2);
    assert_eq!(
        applied
            .iter()
            .find(|g| g.id == "t1:view")
            .map(|g| g.permission.as_str()),
        Some("project.view")
    );
    let both = second
        .apply(&governance, &engine, &actor, &applied, None)
        .expect("applies");
    assert_eq!(both.len(), 3);
}

#[test]
fn materialized_grants_go_through_the_invariants() {
    let engine = engine();
    let governance = Governance::new().with(NoEscalation::new());
    // The actor holds only `project.view`, so the template's `project.edit` is refused.
    let current = vec![Grant::allow(
        "l",
        SubjectMatcher::user("lead"),
        "project.view",
        TargetSelector::kind("project"),
    )];
    let copy = template(1).materialize(SubjectMatcher::user("ana"), None, "t");
    let violations = copy
        .apply(&governance, &engine, &Subject::user("lead"), &current, None)
        .expect_err("refused");
    assert_eq!(violations[0].invariant, "no_escalation");
}

#[test]
fn template_round_trips_through_json() {
    let original = template(4);
    let json = serde_json::to_string(&original).expect("serialize");
    let back: RoleTemplate = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, original);
}
