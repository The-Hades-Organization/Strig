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

fn assert_refused_by_prerequisites(result: Result<Vec<Grant>, Vec<themis::Violation>>) {
    let violations = result.expect_err("refused");
    assert_eq!(violations[0].invariant, "prerequisites");
}

#[test]
fn a_deny_on_a_prerequisite_is_refused_when_someone_holds_the_dependent() {
    let engine = engine();
    let governance = Governance::new().with(Prerequisites);
    let actor = Subject::user("boss");
    let grants = vec![allow("v", "ana", "doc.view"), allow("e", "ana", "doc.edit")];

    let deny_view = Mutation::Add(Grant::deny(
        "d",
        SubjectMatcher::user("ana"),
        "doc.view",
        TargetSelector::kind("project"),
    ));
    assert_refused_by_prerequisites(governance.apply(&engine, &actor, &grants, &deny_view, None));

    // Nobody relies on `doc.view` for `doc.edit` here, so the deny is just a deny.
    let only_view = vec![allow("v", "ana", "doc.view")];
    governance
        .apply(&engine, &actor, &only_view, &deny_view, None)
        .expect("no dependent holder");
}

#[test]
fn revoking_a_role_checks_the_grants_that_come_by_principal_or_any() {
    let engine = engine();
    let governance = Governance::new().with(Prerequisites);
    let actor = Subject::user("boss");
    let viewers = Subject::user("ana").with_role("viewers").with_principal("staff");
    let revoke = Mutation::RevokeRole {
        subject: viewers,
        role: themis::RoleAssignment {
            role: "viewers".into(),
            scope: None,
        },
    };
    let on_projects = TargetSelector::kind("project");
    for holder in [SubjectMatcher::principal("staff"), SubjectMatcher::Any] {
        let grants = vec![
            Grant::allow("v", SubjectMatcher::role("viewers"), "doc.view", on_projects.clone()),
            Grant::allow("e", holder, "doc.edit", on_projects.clone()),
        ];
        // `ana` keeps `doc.edit` (by principal or `any`) but would lose `doc.view` with the role.
        assert_refused_by_prerequisites(governance.apply(&engine, &actor, &grants, &revoke, None));
    }
}

#[test]
fn rejects_a_prerequisite_the_dependent_can_never_share_a_target_with() {
    let errors = Catalog::builder()
        .target_kinds(["project", "document"])
        .permission(PermissionDef::new("doc.view").targets(["document"]))
        .permission(
            PermissionDef::new("proj.edit")
                .targets(["project"])
                .depends_on(["doc.view"]),
        )
        .build()
        .expect_err("unreachable");
    assert!(errors.0.iter().any(|e| matches!(
        e,
        CatalogError::UnreachablePrerequisite { key, prerequisite, target }
            if key == "proj.edit" && prerequisite == "doc.view" && target == "project"
    )));

    let ok = Catalog::builder()
        .target_kinds(["project", "document"])
        .broad_target("org")
        .permission(PermissionDef::new("doc.view").targets(["project", "document"]))
        .permission(
            PermissionDef::new("proj.edit")
                .targets(["project", "org"])
                .depends_on(["doc.view"]),
        )
        .build();
    assert!(ok.is_ok(), "a broad target needs no match: {ok:?}");
}
