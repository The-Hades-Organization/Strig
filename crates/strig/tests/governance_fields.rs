//! Governança e campos: `NoEscalation` não dá campo que o ator não tem; `CatalogConformance`
//! valida os campos de um grant.

use strig::{
    Catalog, CatalogConformance, Engine, Governance, Grant, Mutation, NoEscalation, PermissionDef, Subject,
    SubjectMatcher, TargetSelector, Violation,
};

fn engine() -> Engine {
    let catalog = Catalog::builder()
        .target_kind("document")
        .permission(
            PermissionDef::new("document.edit")
                .targets(["document"])
                .fields(["title", "body", "status"]),
        )
        .build()
        .expect("catalog");
    Engine::builder(catalog).build().expect("engine")
}

fn grant(id: &str, user: &str, effect_allow: bool, fields: &[&str]) -> Grant {
    let target = TargetSelector::kind("document");
    let g = if effect_allow {
        Grant::allow(id, SubjectMatcher::user(user), "document.edit", target)
    } else {
        Grant::deny(id, SubjectMatcher::user(user), "document.edit", target)
    };
    g.fields(fields.iter().copied())
}

fn refused(result: Result<Vec<Grant>, Vec<Violation>>) -> String {
    result.expect_err("refused").remove(0).invariant
}

fn governance() -> Governance {
    Governance::new().with(NoEscalation::new()).with(CatalogConformance)
}

fn lead() -> Subject {
    Subject::user("lead")
}

#[test]
fn an_actor_can_hand_out_the_fields_they_hold() {
    let engine = engine();
    let grants = vec![grant("l", "lead", true, &["title", "body"])];
    let give = Mutation::Add(grant("a", "ana", true, &["title"]));
    governance()
        .apply(&engine, &lead(), &grants, &give, None)
        .expect("title is held");
}

#[test]
fn an_actor_cannot_hand_out_a_field_they_lack() {
    let engine = engine();
    let grants = vec![grant("l", "lead", true, &["title"])];
    let give = Mutation::Add(grant("a", "ana", true, &["title", "status"]));
    assert_eq!(
        refused(governance().apply(&engine, &lead(), &grants, &give, None)),
        "no_escalation"
    );
}

#[test]
fn a_field_restricted_holder_cannot_hand_out_the_whole_resource() {
    let engine = engine();
    let grants = vec![grant("l", "lead", true, &["title"])];
    let give = Mutation::Add(grant("a", "ana", true, &[]));
    assert_eq!(
        refused(governance().apply(&engine, &lead(), &grants, &give, None)),
        "no_escalation"
    );
}

#[test]
fn a_holder_of_the_whole_resource_can_hand_out_a_field() {
    let engine = engine();
    let grants = vec![grant("l", "lead", true, &[])];
    let give = Mutation::Add(grant("a", "ana", true, &["status"]));
    governance()
        .apply(&engine, &lead(), &grants, &give, None)
        .expect("whole covers the field");
}

#[test]
fn lifting_a_field_deny_needs_the_field() {
    let engine = engine();
    let grants = vec![
        grant("l", "lead", true, &["title"]),
        grant("d", "ana", false, &["status"]),
    ];
    let lift = Mutation::Remove { id: "d".into() };
    assert_eq!(
        refused(governance().apply(&engine, &lead(), &grants, &lift, None)),
        "no_escalation"
    );
}

#[test]
fn catalog_conformance_refuses_a_field_the_catalog_does_not_declare() {
    let engine = engine();
    let grants = vec![grant("l", "lead", true, &[])];
    let bad = Mutation::Add(grant("a", "ana", true, &["titel"]));
    assert_eq!(
        refused(governance().apply(&engine, &lead(), &grants, &bad, None)),
        "catalog_conformance"
    );
}
