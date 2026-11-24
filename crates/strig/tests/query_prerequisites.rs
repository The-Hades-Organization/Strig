//! Listing and reverse queries keep `depends_on`: an allow only stands where every prerequisite
//! is allowed on the same resource, as in `Engine::check`.

use strig::{
    Catalog, Engine, Grant, InMemorySubjects, PathLayout, PermissionDef, QueryContext, Request, Resource, Subject,
    SubjectMatcher, SubjectRef, TargetSelector,
};

fn engine() -> Engine {
    let catalog = Catalog::builder()
        .target_kind("project")
        .permission(PermissionDef::new("doc.view").targets(["project"]))
        .permission(
            PermissionDef::new("doc.edit")
                .targets(["project"])
                .depends_on(["doc.view"]),
        )
        .build()
        .expect("catalog");
    Engine::builder(catalog).build().expect("engine")
}

fn projects() -> Vec<Resource> {
    ["p1", "p2", "p3"]
        .iter()
        .map(|id| Resource::new("project", *id))
        .collect()
}

fn grants() -> Vec<Grant> {
    let on = |id: &str| TargetSelector::exact("project", id);
    let user = || SubjectMatcher::user("u1");
    vec![
        // p1: edit and view. p2: edit without view. p3: view only.
        Grant::allow("edit-p1", user(), "doc.edit", on("p1")),
        Grant::allow("view-p1", user(), "doc.view", on("p1")),
        Grant::allow("edit-p2", user(), "doc.edit", on("p2")),
        Grant::allow("view-p3", user(), "doc.view", on("p3")),
    ]
}

#[test]
fn a_listing_drops_the_resources_missing_a_prerequisite() {
    let engine = engine();
    let grants = grants();
    let qctx = QueryContext::new(&grants);
    let subject = Subject::user("u1");
    let filter = engine.list(&qctx, &subject, "doc.edit", "project");
    let all = projects();
    let ctx = qctx.context();
    let listed = filter.resolve_with(&engine, &ctx, &all);
    assert_eq!(listed, ["p1"]);
    for resource in &all {
        let checked = engine.check(&ctx, &Request::new(&subject, "doc.edit", resource));
        assert_eq!(filter.allows(resource) == strig::FilterOutcome::Allowed, checked);
    }
}

#[test]
fn the_structural_form_carries_the_prerequisite() {
    let engine = engine();
    let grants = grants();
    let qctx = QueryContext::new(&grants);
    let filter = engine.list(&qctx, &Subject::user("u1"), "doc.edit", "project");
    let expr = filter.expr(&PathLayout::new("project"));
    for resource in projects() {
        let holds = expr.holds(&resource, &|_| None);
        assert_eq!(
            holds,
            Some(resource.primary().and_then(|a| a.id.as_deref()) == Some("p1"))
        );
    }
}

#[test]
fn reverse_queries_agree_with_the_prerequisite() {
    let engine = engine();
    let grants = grants();
    let qctx = QueryContext::new(&grants);
    let me = SubjectRef::User { id: "u1".into() };
    let resolver = InMemorySubjects::new().with(Subject::user("u1"));
    for resource in projects() {
        let checked = engine.check(
            &qctx.context(),
            &Request::new(&Subject::user("u1"), "doc.edit", &resource),
        );
        let listed = engine
            .who_can_on(&qctx, "doc.edit", &resource)
            .unwrap()
            .subjects()
            .any(|s| *s == me);
        assert_eq!(listed, checked);
        let answer = engine.check_for(&qctx, &resolver, &me, "doc.edit", &resource).unwrap();
        assert_eq!(answer.decision.is_allowed(), checked);
    }
}
