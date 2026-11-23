//! Listing: the filter of `Engine::list` agrees with `Engine::check` for every resource.

mod support;

use std::collections::BTreeSet;

use support::*;
use themis::{
    Anchor, Condition, Context, DenyOverrides, Engine, FilterResidual, FilterShape, FirstApplicable, Grant,
    InMemoryTuples, ObjectRef, Operand, PathLayout, PermitOverrides, QueryContext, RelationSchema, Request, Resource,
    Rewrite, RoleGraph, Subject, SubjectMatcher, TargetSelector, Tuple,
};

const PROJECTS: [(&str, &str); 3] = [("p1", "o1"), ("p2", "o1"), ("p3", "o2")];

fn layout() -> PathLayout {
    PathLayout::new("document")
        .within("doc_type")
        .within("project")
        .within("org")
}

/// Documents spread over three projects, two organizations and the three document types. Some are
/// owned, some are drafts.
fn documents() -> Vec<Resource> {
    let mut out = Vec::new();
    let mut n = 0;
    for (project, org) in PROJECTS {
        for ty in DOC_TYPES {
            for _ in 0..2 {
                n += 1;
                let mut doc = Resource::new("document", format!("d{n}"))
                    .within("doc_type", *ty)
                    .within("project", project)
                    .within("org", org);
                if n % 5 == 0 {
                    doc = doc.with_attr("owner", "carol");
                }
                if n % 3 == 0 {
                    doc = doc.with_attr("status", "draft");
                }
                out.push(doc);
            }
        }
    }
    out
}

fn tuples() -> InMemoryTuples {
    let project = |id: &str| ObjectRef::new("project", id);
    [
        Tuple::new(project("p1"), "editor", ObjectRef::new("user", "erin")),
        Tuple::new(project("p3"), "owner", ObjectRef::new("user", "frank")),
        Tuple::userset(project("p2"), "viewer", ObjectRef::new("team", "t1"), "member"),
        Tuple::new(ObjectRef::new("team", "t1"), "member", ObjectRef::new("user", "gina")),
    ]
    .into_iter()
    .collect()
}

fn schema() -> RelationSchema {
    RelationSchema::new()
        .relation(
            "project",
            "editor",
            Rewrite::union([Rewrite::This, Rewrite::computed("owner")]),
        )
        .relation(
            "project",
            "viewer",
            Rewrite::union([Rewrite::This, Rewrite::computed("editor")]),
        )
}

fn grants() -> Vec<Grant> {
    let draft = Condition::eq(Operand::attr("resource.status"), Operand::lit("draft"));
    let project_p2 = TargetSelector::exact("project", "p2");
    let org_two = TargetSelector::exact("org", "o2");
    vec![
        // RBAC: members view every document of the organization, but not reports.
        role_grant("view", "member", "document.view", true, at_org()),
        role_grant(
            "no-reports",
            "member",
            "document.report.view",
            false,
            TargetSelector::kind("doc_type"),
        ),
        // Inherited role: maintainers export through the member grant of the organization.
        role_grant("export", "member", "document.export", true, at_org()),
        // Scoped to a project.
        role_grant("edit-p2", "editor", "document.edit", true, project_p2),
        // ABAC: members edit the drafts of the organization.
        role_grant("edit-drafts", "member", "document.edit", true, at_org()).when(draft),
        // Single resource.
        Grant::allow(
            "bob-d3",
            SubjectMatcher::user("bob"),
            "document.export",
            TargetSelector::exact("document", "d3"),
        ),
        // Principal and everyone.
        Grant::allow(
            "auditors",
            SubjectMatcher::principal("auditor"),
            "document.view",
            TargetSelector::global(),
        ),
        Grant::deny(
            "no-o2-for-guests",
            SubjectMatcher::role("guest"),
            "document.view",
            org_two.clone(),
        ),
        Grant::allow(
            "guest-view",
            SubjectMatcher::role("guest"),
            "document.view",
            TargetSelector::global(),
        ),
        // ReBAC.
        Grant::allow(
            "viewers",
            SubjectMatcher::relation("viewer"),
            "document.view",
            TargetSelector::kind("project"),
        ),
        Grant::allow(
            "editors",
            SubjectMatcher::relation("editor"),
            "document.edit",
            TargetSelector::kind("project"),
        ),
        Grant::deny(
            "locked-p3",
            SubjectMatcher::relation("editor"),
            "document.edit",
            TargetSelector::exact("project", "p3"),
        ),
        // Org-wide manage, through the override of the permission holder.
        role_grant("manage", "admin", "org.manage", true, at_org()),
        Grant::allow("o2-admin", SubjectMatcher::user("hank"), "org.manage", org_two),
    ]
}

fn subjects() -> Vec<Subject> {
    vec![
        Subject::user("u1").with_role_in("member", org()),
        Subject::user("u2").with_role_in("maintainer", org()),
        Subject::user("u3").with_role_in("editor", org()),
        Subject::user("u4").with_role_in("admin", org()),
        Subject::user("u5").with_role_in("member", org()).with_role("guest"),
        Subject::user("bob"),
        Subject::user("carol").with_role_in("member", org()),
        Subject::user("dave").with_principal("auditor"),
        Subject::user("erin"),
        Subject::user("frank"),
        Subject::user("gina"),
        Subject::user("hank"),
        Subject::user("zed").with_role("guest"),
        Subject::anonymous(),
    ]
}

const PERMISSIONS: [&str; 8] = [
    "document.view",
    "document.report.view",
    "document.invoice.view",
    "document.edit",
    "document.export",
    "document.contract.export",
    "project.view",
    "nonexistent.permission",
];

fn roles() -> RoleGraph {
    RoleGraph::builder().inherit("maintainer", "member").build().unwrap()
}

fn engines() -> Vec<(&'static str, Engine)> {
    let build = |builder: themis::EngineBuilder| builder.roles(roles()).relations(schema());
    let base = || {
        Engine::builder(catalog())
            .override_with(themis::ResourceOwner::new("owner"))
            .override_with(themis::PermissionHolder::new("org.manage"))
    };
    vec![
        ("most_specific", build(base()).build().unwrap()),
        ("deny_overrides", build(base().strategy(DenyOverrides)).build().unwrap()),
        (
            "permit_overrides",
            build(base().strategy(PermitOverrides)).build().unwrap(),
        ),
        (
            "first_applicable",
            build(base().strategy(FirstApplicable)).build().unwrap(),
        ),
    ]
}

/// No overrides: the reach is what the grants alone describe.
fn plain_engine() -> Engine {
    Engine::builder(catalog()).build().unwrap()
}

fn allowed_by_check(
    engine: &Engine,
    ctx: &Context<'_>,
    subject: &Subject,
    key: &str,
    docs: &[Resource],
) -> BTreeSet<String> {
    docs.iter()
        .filter(|doc| engine.check(ctx, &Request::new(subject, key, doc)))
        .filter_map(|doc| doc.primary().and_then(|a| a.id.clone()))
        .collect()
}

#[test]
fn filter_matches_check_for_every_resource_subject_and_permission() {
    let (grants, store, docs) = (grants(), tuples(), documents());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let ctx = qctx.context();
    for (name, engine) in engines() {
        for subject in subjects() {
            for key in PERMISSIONS {
                let expected = allowed_by_check(&engine, &ctx, &subject, key, &docs);
                let filter = engine.list(&qctx, &subject, key, "document");
                let settled: BTreeSet<String> = filter.resolve_with(&engine, &ctx, &docs).into_iter().collect();
                assert_eq!(
                    settled, expected,
                    "strategy {name}, subject {:?}, permission {key}",
                    subject.id
                );
            }
        }
    }
}

#[test]
fn undecided_resources_are_never_reported_as_allowed() {
    let (grants, store, docs) = (grants(), tuples(), documents());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let ctx = qctx.context();
    for (name, engine) in engines() {
        for subject in subjects() {
            for key in PERMISSIONS {
                let expected = allowed_by_check(&engine, &ctx, &subject, key, &docs);
                let resolution = engine.list(&qctx, &subject, key, "document").resolve(&docs);
                let allowed: BTreeSet<String> = resolution.allowed.iter().cloned().collect();
                let undecided: BTreeSet<String> = resolution.undecided.iter().cloned().collect();
                assert!(allowed.is_subset(&expected), "strategy {name}, {:?}, {key}", subject.id);
                assert!(
                    expected.difference(&allowed).all(|id| undecided.contains(id)),
                    "strategy {name}, {:?}, {key}: an allowed resource is neither allowed nor undecided",
                    subject.id
                );
            }
        }
    }
}

#[test]
fn structural_form_is_sound_and_its_bounds_bracket_the_decision() {
    let (grants, store, docs) = (grants(), tuples(), documents());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let ctx = qctx.context();
    let layout = layout();
    for (name, engine) in engines() {
        for subject in subjects() {
            for key in PERMISSIONS {
                let filter = engine.list(&qctx, &subject, key, "document");
                let expr = filter.expr(&layout);
                let (lower, upper) = expr.bounds();
                for doc in &docs {
                    let allowed = engine.check(&ctx, &Request::new(&subject, key, doc));
                    let context = format!("strategy {name}, {:?}, {key}, {:?}", subject.id, doc.primary());
                    if let Some(decided) = expr.holds(doc, &|_| None) {
                        assert_eq!(decided, allowed, "{context}");
                    }
                    if lower.holds(doc, &|_| None) == Some(true) {
                        assert!(allowed, "lower bound admits a denied resource: {context}");
                    }
                    if upper.holds(doc, &|_| None) == Some(false) {
                        assert!(!allowed, "upper bound rejects an allowed resource: {context}");
                    }
                }
            }
        }
    }
}

#[test]
fn filter_without_residue_is_decided_by_structure_alone() {
    let (grants, store, docs) = (grants(), tuples(), documents());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let ctx = qctx.context();
    let layout = layout();
    let engine = &engines()[0].1;
    let subject = Subject::user("u1").with_role_in("member", org());
    let filter = engine.list(&qctx, &subject, "document.view", "document");
    assert!(filter.is_exact(&layout));
    let expr = filter.expr(&layout);
    for doc in &docs {
        let allowed = engine.check(&ctx, &Request::new(&subject, "document.view", doc));
        assert_eq!(expr.holds(doc, &|_| None), Some(allowed));
    }
}

#[test]
fn condition_over_a_resource_attribute_is_a_residue_never_an_allow() {
    let (grants, store) = (grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let engine = &engines()[0].1;
    let subject = Subject::user("u1").with_role_in("member", org());
    let filter = engine.list(&qctx, &subject, "document.edit", "document");
    assert!(
        filter
            .residual()
            .iter()
            .any(|r| matches!(r, FilterResidual::Condition { grant_id, .. } if grant_id == "edit-drafts"))
    );
    assert!(!filter.is_exact(&layout()));
    let draft = Resource::new("document", "x1")
        .within("doc_type", "invoice")
        .within("project", "p1")
        .within("org", "o1")
        .with_attr("status", "draft");
    let published = draft.clone().with_attr("status", "published");
    assert_eq!(filter.resolve([&draft, &published]).allowed, vec!["x1".to_string()]);
    let layout_expr = filter.expr(&layout());
    assert_eq!(layout_expr.holds(&draft, &|_| None), None);
}

#[test]
fn whole_kind_is_reported_without_enumerating() {
    let grants = vec![Grant::allow(
        "all",
        SubjectMatcher::Any,
        "document.view",
        TargetSelector::global(),
    )];
    let qctx = QueryContext::new(&grants);
    let engine = &plain_engine();
    let filter = engine.list(&qctx, &Subject::user("anyone"), "document.view", "document");
    assert_eq!(
        filter.shape(&layout()),
        FilterShape::Kind {
            except: BTreeSet::new()
        }
    );
}

#[test]
fn scoped_reach_is_reported_as_anchors() {
    let grants = vec![Grant::allow(
        "p2",
        SubjectMatcher::user("u9"),
        "document.view",
        TargetSelector::exact("project", "p2"),
    )];
    let qctx = QueryContext::new(&grants);
    let engine = &plain_engine();
    let filter = engine.list(&qctx, &Subject::user("u9"), "document.view", "document");
    assert_eq!(
        filter.shape(&layout()),
        FilterShape::Within(vec![Anchor::new("project", "p2")])
    );
}

#[test]
fn single_resource_grant_is_reported_as_ids() {
    let grants = vec![Grant::allow(
        "d3",
        SubjectMatcher::user("u9"),
        "document.view",
        TargetSelector::exact("document", "d3"),
    )];
    let qctx = QueryContext::new(&grants);
    let engine = &plain_engine();
    let filter = engine.list(&qctx, &Subject::user("u9"), "document.view", "document");
    assert_eq!(
        filter.shape(&layout()),
        FilterShape::Ids(BTreeSet::from(["d3".to_string()]))
    );
}

#[test]
fn nothing_is_reported_for_a_subject_without_grants_and_for_unknown_permissions() {
    let (grants, store) = (grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let engine = &plain_engine();
    let stranger = Subject::user("nobody");
    assert_eq!(
        engine
            .list(&qctx, &stranger, "document.view", "document")
            .shape(&layout()),
        FilterShape::Nothing
    );
    let member = Subject::user("u1").with_role_in("member", org());
    assert_eq!(
        engine
            .list(&qctx, &member, "nonexistent.permission", "document")
            .shape(&layout()),
        FilterShape::Nothing
    );
}

#[test]
fn relation_grant_without_a_tuple_store_lists_nothing_and_warns() {
    let grants = grants();
    let qctx = QueryContext::new(&grants);
    let engine = &engines()[0].1;
    let filter = engine.list(&qctx, &Subject::user("erin"), "document.view", "document");
    assert!(filter.resolve(&documents()).allowed.is_empty());
    assert!(!filter.warnings().is_empty());
}

#[test]
fn filter_of_another_kind_denies_everything() {
    let (grants, store) = (grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let engine = &engines()[0].1;
    let member = Subject::user("u1").with_role_in("member", org());
    let filter = engine.list(&qctx, &member, "project.view", "project");
    let doc = documents().remove(0);
    assert!(filter.resolve([&doc]).allowed.is_empty());
}
