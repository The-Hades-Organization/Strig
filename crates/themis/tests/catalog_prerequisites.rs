//! `depends_on` in the catalog, in the decision and in governance, and `override_only` grants.

use themis::{
    Catalog, CatalogError, Context, Effect, Engine, Governance, Grant, GrantError, Mutation, PermissionDef,
    Prerequisites, Reason, Request, Resource, Subject, SubjectMatcher, TargetSelector, Verdict,
};

fn catalog() -> Catalog {
    Catalog::builder()
        .target_kind("project")
        .permission(PermissionDef::new("doc.view").targets(["project"]))
        .permission(
            PermissionDef::new("doc.edit")
                .targets(["project"])
                .depends_on(["doc.view"]),
        )
        .permission(
            PermissionDef::new("doc.publish")
                .targets(["project"])
                .depends_on(["doc.edit"]),
        )
        .permission(
            PermissionDef::new("doc.break_glass")
                .targets(["project"])
                .override_only(),
        )
        .build()
        .expect("catalog")
}

fn engine() -> Engine {
    Engine::builder(catalog()).build().expect("engine")
}

fn project() -> Resource {
    Resource::new("project", "p1")
}

fn allow(id: &str, user: &str, key: &str) -> Grant {
    Grant::allow(id, SubjectMatcher::user(user), key, TargetSelector::kind("project"))
}

#[test]
fn rejects_prerequisite_cycle() {
    let errors = Catalog::builder()
        .target_kind("project")
        .permission(PermissionDef::new("a").targets(["project"]).depends_on(["b"]))
        .permission(PermissionDef::new("b").targets(["project"]).depends_on(["a"]))
        .build()
        .expect_err("cycle");
    assert!(errors.0.iter().any(|e| matches!(e, CatalogError::PrerequisiteCycle(_))));
}

#[test]
fn rejects_unknown_prerequisite() {
    let errors = Catalog::builder()
        .target_kind("project")
        .permission(PermissionDef::new("a").targets(["project"]).depends_on(["ghost"]))
        .build()
        .expect_err("unknown");
    assert!(
        errors
            .0
            .iter()
            .any(|e| matches!(e, CatalogError::UnknownPrerequisite { .. }))
    );
}

#[test]
fn allow_without_prerequisite_is_denied_with_its_own_reason() {
    let engine = engine();
    let grants = vec![allow("g", "ana", "doc.edit")];
    let ana = Subject::user("ana");
    let decision = engine.decide(&Context::new(&grants), &Request::new(&ana, "doc.edit", &project()));
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(
        decision.reason,
        Reason::MissingPrerequisite {
            permission: "doc.edit".into(),
            prerequisite: "doc.view".into()
        }
    );
}

#[test]
fn allow_with_prerequisite_on_the_same_resource_stands() {
    let engine = engine();
    let grants = vec![allow("g1", "ana", "doc.edit"), allow("g2", "ana", "doc.view")];
    let ana = Subject::user("ana");
    assert!(engine.check(&Context::new(&grants), &Request::new(&ana, "doc.edit", &project())));
}

#[test]
fn prerequisites_are_transitive_and_explained() {
    let engine = engine();
    let grants = vec![allow("g1", "ana", "doc.publish"), allow("g2", "ana", "doc.edit")];
    let ana = Subject::user("ana");
    let resource = project();
    let request = Request::new(&ana, "doc.publish", &resource);
    let explanation = engine.explain(&Context::new(&grants), &request);
    assert!(matches!(
        explanation.decision.reason,
        Reason::MissingPrerequisite { ref prerequisite, .. } if prerequisite == "doc.view"
    ));
    let steps: Vec<_> = explanation
        .prerequisites
        .iter()
        .map(|s| (s.permission.as_str(), s.allowed))
        .collect();
    assert!(steps.contains(&("doc.view", false)));
    assert!(steps.contains(&("doc.edit", true)));
}

#[test]
fn prerequisite_on_another_resource_does_not_count() {
    let engine = engine();
    let grants = vec![
        allow("g1", "ana", "doc.edit"),
        Grant::allow(
            "g2",
            SubjectMatcher::user("ana"),
            "doc.view",
            TargetSelector::exact("project", "p2"),
        ),
    ];
    let ana = Subject::user("ana");
    assert!(!engine.check(&Context::new(&grants), &Request::new(&ana, "doc.edit", &project())));
}

#[test]
fn override_only_grant_is_refused_and_ignored() {
    let engine = engine();
    let grant = allow("g", "ana", "doc.break_glass");
    assert!(matches!(
        engine.validate_grant(&grant),
        Err(GrantError::OverrideOnly(_))
    ));
    let grants = vec![grant];
    let ana = Subject::user("ana");
    let resource = project();
    let request = Request::new(&ana, "doc.break_glass", &resource);
    assert!(!engine.check(&Context::new(&grants), &request));
    let explanation = engine.explain(&Context::new(&grants), &request);
    assert!(explanation.grants.iter().any(|t| t.verdict == Verdict::OverrideOnly));
}

#[test]
fn governance_refuses_permission_without_prerequisite() {
    let engine = engine();
    let governance = Governance::new().with(Prerequisites);
    let actor = Subject::user("boss");
    let add = Mutation::Add(allow("g", "ana", "doc.edit"));
    let violations = governance.apply(&engine, &actor, &[], &add, None).expect_err("refused");
    assert_eq!(violations[0].invariant, "prerequisites");

    let with_view = vec![allow("v", "ana", "doc.view")];
    let after = governance
        .apply(&engine, &actor, &with_view, &add, None)
        .expect("accepted");
    assert_eq!(after.len(), 2);
}

#[test]
fn governance_refuses_removing_a_prerequisite_in_use() {
    let engine = engine();
    let governance = Governance::new().with(Prerequisites);
    let actor = Subject::user("boss");
    let grants = vec![allow("v", "ana", "doc.view"), allow("e", "ana", "doc.edit")];
    let remove = Mutation::Remove { id: "v".into() };
    let violations = governance
        .apply(&engine, &actor, &grants, &remove, None)
        .expect_err("refused");
    assert_eq!(violations[0].invariant, "prerequisites");

    let remove_both = Mutation::Remove { id: "e".into() };
    governance
        .apply(&engine, &actor, &grants, &remove_both, None)
        .expect("dependent first");
}
