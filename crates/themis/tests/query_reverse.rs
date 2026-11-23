//! Reverse queries: who can do X, who can do X on Y, who reaches Z, and X on Z for one subject.

mod support;

use support::*;
use themis::{
    AccessVia, Condition, Engine, Grant, InMemorySubjects, InMemoryTuples, ObjectRef, Operand, PermissionHolder,
    QueryContext, QueryError, RelationSchema, Request, Resource, ResourceOwner, Rewrite, RoleGraph, Subject,
    SubjectMatcher, SubjectRef, TargetSelector, Tuple,
};

fn engine_with_roles() -> Engine {
    let roles = RoleGraph::builder().inherit("maintainer", "member").build().unwrap();
    let schema = RelationSchema::new().relation(
        "project",
        "viewer",
        Rewrite::union([Rewrite::This, Rewrite::computed("editor")]),
    );
    Engine::builder(catalog())
        .roles(roles)
        .relations(schema)
        .override_with(ResourceOwner::new("owner"))
        .override_with(PermissionHolder::new("org.manage"))
        .build()
        .unwrap()
}

fn grants() -> Vec<Grant> {
    vec![
        role_grant("view", "member", "document.view", true, at_org()),
        role_grant(
            "no-reports",
            "member",
            "document.report.view",
            false,
            TargetSelector::kind("doc_type"),
        ),
        role_grant("manage", "admin", "org.manage", true, at_org()),
        Grant::allow(
            "bob-export",
            SubjectMatcher::user("bob"),
            "document.export",
            TargetSelector::exact("project", PROJECT),
        ),
        Grant::allow(
            "auditors",
            SubjectMatcher::principal("auditor"),
            "document.view",
            TargetSelector::global(),
        ),
        Grant::allow(
            "viewers",
            SubjectMatcher::relation("viewer"),
            "document.view",
            TargetSelector::kind("project"),
        ),
        Grant::allow(
            "edit-drafts",
            SubjectMatcher::role("member"),
            "document.edit",
            TargetSelector::exact("org", ORG),
        )
        .when(Condition::eq(Operand::attr("resource.status"), Operand::lit("draft"))),
    ]
}

fn tuples() -> InMemoryTuples {
    [
        Tuple::new(
            ObjectRef::new("project", PROJECT),
            "viewer",
            ObjectRef::new("user", "erin"),
        ),
        Tuple::userset(
            ObjectRef::new("project", PROJECT),
            "viewer",
            ObjectRef::new("team", "t1"),
            "member",
        ),
        Tuple::new(ObjectRef::new("team", "t1"), "member", ObjectRef::new("user", "gina")),
    ]
    .into_iter()
    .collect()
}

fn people() -> Vec<Subject> {
    vec![
        Subject::user("u1").with_role_in("member", org()),
        Subject::user("u2").with_role_in("maintainer", org()),
        Subject::user("u4").with_role_in("admin", org()),
        Subject::user("bob"),
        Subject::user("carol").with_role_in("member", org()),
        Subject::user("dave").with_principal("auditor"),
        Subject::user("erin"),
        Subject::user("gina"),
        Subject::user("nobody"),
    ]
}

fn resolver() -> InMemorySubjects {
    people()
        .into_iter()
        .fold(InMemorySubjects::new(), InMemorySubjects::with)
}

fn doc() -> Resource {
    document("d1", "report").with_attr("owner", "carol")
}

#[test]
fn who_can_on_agrees_with_check_subject_by_subject() {
    let (engine, grants, store) = (engine_with_roles(), grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let ctx = qctx.context();
    let resources = [
        doc(),
        document("d2", "invoice"),
        document("d3", "contract").with_attr("status", "draft"),
        project(),
    ];
    for resource in &resources {
        for key in [
            "document.view",
            "document.report.view",
            "document.export",
            "document.edit",
            "project.view",
        ] {
            let who = engine.who_can_on(&qctx, key, resource);
            for subject in people() {
                let expected = engine.check(&ctx, &Request::new(&subject, key, resource));
                assert_eq!(
                    who.admits(&engine, Some(&store), &subject),
                    expected,
                    "{key} on {:?} for {:?}",
                    resource.primary(),
                    subject.id
                );
            }
        }
    }
}

#[test]
fn who_can_names_the_kind_of_each_party_without_expanding_roles() {
    let (engine, grants, store) = (engine_with_roles(), grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let parties = engine.who_can(&qctx, "document.view");
    assert!(parties.contains(&SubjectRef::Role { id: "member".into() }));
    assert!(parties.contains(&SubjectRef::Principal { name: "auditor".into() }));
    assert!(parties.contains(&SubjectRef::User { id: "erin".into() }));
    assert!(parties.contains(&SubjectRef::Userset {
        object: ObjectRef::new("team", "t1"),
        relation: "member".into()
    }));
    assert!(!parties.contains(&SubjectRef::User { id: "u1".into() }));
}

#[test]
fn who_can_follows_implication_and_ignores_denies() {
    let (engine, grants, store) = (engine_with_roles(), grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let parties = engine.who_can(&qctx, "document.report.view");
    assert!(parties.contains(&SubjectRef::Role { id: "member".into() }));
    assert!(engine.who_can(&qctx, "nonexistent.permission").is_empty());
}

#[test]
fn who_can_on_leaves_out_a_party_that_a_deny_removes() {
    let (engine, grants, store) = (engine_with_roles(), grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let who = engine.who_can_on(&qctx, "document.report.view", &document("d9", "report"));
    assert!(
        !who.subjects()
            .any(|s| matches!(s, SubjectRef::Role { id } if id == "member"))
    );
}

#[test]
fn who_can_on_reports_the_override_holder_and_the_owner() {
    let (engine, grants, store) = (engine_with_roles(), grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let who = engine.who_can_on(&qctx, "document.export", &doc());
    assert!(
        who.subjects()
            .any(|s| matches!(s, SubjectRef::User { id } if id == "carol"))
    );
    assert!(
        who.subjects()
            .any(|s| matches!(s, SubjectRef::Role { id } if id == "admin"))
    );
    assert!(
        who.subjects()
            .any(|s| matches!(s, SubjectRef::User { id } if id == "bob"))
    );
}

#[test]
fn access_of_lists_each_party_with_its_permissions() {
    let (engine, grants, store) = (engine_with_roles(), grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let access = engine.access_of(&qctx, &document("d2", "invoice"));
    let of = |party: &SubjectRef| access.iter().find(|a| &a.subject == party).map(|a| &a.permissions);
    let member = of(&SubjectRef::Role { id: "member".into() }).expect("member listed");
    assert!(member.contains("document.view"));
    assert!(member.contains("document.invoice.view"));
    assert!(!member.contains("document.export"));
    let bob = of(&SubjectRef::User { id: "bob".into() }).expect("bob listed");
    assert!(bob.contains("document.export"));
    assert!(of(&SubjectRef::User { id: "nobody".into() }).is_none());
}

#[test]
fn check_for_explains_a_direct_role_grant() {
    let (engine, grants, store) = (engine_with_roles(), grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let answer = engine
        .check_for(
            &qctx,
            &resolver(),
            &SubjectRef::User { id: "u1".into() },
            "document.view",
            &document("d2", "invoice"),
        )
        .unwrap();
    assert!(answer.is_allowed());
    assert_eq!(
        answer.via,
        AccessVia::Role {
            grant_id: "view".into(),
            role: "member".into()
        }
    );
}

#[test]
fn check_for_explains_an_inherited_role() {
    let (engine, grants, store) = (engine_with_roles(), grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let answer = engine
        .check_for(
            &qctx,
            &resolver(),
            &SubjectRef::User { id: "u2".into() },
            "document.view",
            &document("d2", "invoice"),
        )
        .unwrap();
    assert_eq!(
        answer.via,
        AccessVia::InheritedRole {
            grant_id: "view".into(),
            role: "member".into(),
            from: "maintainer".into()
        }
    );
}

#[test]
fn check_for_explains_a_relation_and_a_userset() {
    let (engine, grants, store) = (engine_with_roles(), grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    for user in ["erin", "gina"] {
        let answer = engine
            .check_for(
                &qctx,
                &resolver(),
                &SubjectRef::User { id: user.into() },
                "document.view",
                &document("d2", "invoice"),
            )
            .unwrap();
        assert_eq!(
            answer.via,
            AccessVia::Relation {
                grant_id: "viewers".into(),
                relation: "viewer".into(),
                object: ObjectRef::new("project", PROJECT)
            },
            "{user}"
        );
    }
}

#[test]
fn check_for_explains_an_override_and_a_refusal() {
    let (engine, grants, store) = (engine_with_roles(), grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let owner = engine
        .check_for(
            &qctx,
            &resolver(),
            &SubjectRef::User { id: "carol".into() },
            "document.export",
            &doc(),
        )
        .unwrap();
    assert!(owner.is_allowed());
    assert!(matches!(owner.via, AccessVia::Override { .. }));
    let stranger = engine
        .check_for(
            &qctx,
            &resolver(),
            &SubjectRef::User { id: "nobody".into() },
            "document.view",
            &doc(),
        )
        .unwrap();
    assert!(!stranger.is_allowed());
    assert_eq!(stranger.via, AccessVia::Nothing);
}

#[test]
fn check_for_an_unknown_user_is_an_error() {
    let (engine, grants) = (engine_with_roles(), grants());
    let qctx = QueryContext::new(&grants);
    let missing = SubjectRef::User { id: "ghost".into() };
    let err = engine
        .check_for(&qctx, &resolver(), &missing, "document.view", &doc())
        .unwrap_err();
    assert_eq!(err, QueryError::UnknownSubject(missing));
}

#[test]
fn check_for_a_role_that_the_resolver_does_not_know_answers_as_the_role_alone() {
    let (engine, grants) = (engine_with_roles(), grants());
    let qctx = QueryContext::new(&grants);
    let answer = engine
        .check_for(
            &qctx,
            &resolver(),
            &SubjectRef::Role { id: "member".into() },
            "document.view",
            &document("d2", "invoice"),
        )
        .unwrap();
    assert!(answer.is_allowed());
}

#[test]
fn check_for_through_a_closure_resolver() {
    let (engine, grants) = (engine_with_roles(), grants());
    let qctx = QueryContext::new(&grants);
    let resolver = |reference: &SubjectRef| match reference {
        SubjectRef::User { id } => Some(Subject::user(id.clone()).with_role_in("member", org())),
        _ => None,
    };
    let answer = engine
        .check_for(
            &qctx,
            &resolver,
            &SubjectRef::User { id: "anyone".into() },
            "document.view",
            &document("d2", "invoice"),
        )
        .unwrap();
    assert!(answer.is_allowed());
}
