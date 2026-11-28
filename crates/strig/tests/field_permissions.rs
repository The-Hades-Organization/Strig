//! Permissão por campo: o que um grant com campos dá e tira, como combina com as estratégias, com
//! `implied_by` e `depends_on`, e que uma política sem campos decide como sempre decidiu.

use strig::{
    Catalog, Condition, Context, Effect, Engine, FieldSet, Grant, GrantError, Operand, PermissionDef, Reason, Request,
    Resource, Subject, SubjectMatcher, TargetSelector,
};
use strig::{DenyOverrides, FirstApplicable, PermitOverrides, Strategy};

fn catalog(declare: bool) -> Catalog {
    let edit = PermissionDef::new("document.edit")
        .targets(["document", "project"])
        .implied_by(["document.manage"])
        .depends_on(["document.view"]);
    Catalog::builder()
        .target_kinds(["document", "project"])
        .permission(PermissionDef::new("document.view").targets(["document", "project"]))
        .permission(if declare {
            edit.fields(["title", "body", "status"])
        } else {
            edit
        })
        .permission(PermissionDef::new("document.manage").targets(["document", "project"]))
        .build()
        .expect("catálogo")
}

fn engine(declare: bool) -> Engine {
    Engine::builder(catalog(declare)).build().expect("motor")
}

fn engine_with(declare: bool, strategy: impl Strategy + 'static) -> Engine {
    Engine::builder(catalog(declare))
        .strategy(strategy)
        .build()
        .expect("motor")
}

fn ana() -> Subject {
    Subject::user("ana").with_role("editor")
}

fn doc() -> Resource {
    Resource::new("document", "d1").within("project", "p1")
}

fn editor(id: &str, effect: Effect, permission: &str, target: TargetSelector) -> Grant {
    Grant::new(id, effect, SubjectMatcher::role("editor"), permission, target)
}

fn view() -> Grant {
    editor("view", Effect::Allow, "document.view", TargetSelector::kind("project"))
}

fn fields(engine: &Engine, grants: &[Grant], permission: &str) -> FieldSet {
    engine.allowed_fields(&Context::new(&grants), &ana(), permission, &doc())
}

fn can(engine: &Engine, grants: &[Grant], permission: &str, field: Option<&str>) -> bool {
    let subject = ana();
    let resource = doc();
    let request = Request::new(&subject, permission, &resource);
    let request = field.map_or(request, |f| request.field(f));
    engine.check(&Context::new(&grants), &request)
}

fn set<const N: usize>(names: [&str; N]) -> std::collections::BTreeSet<String> {
    names.into_iter().map(String::from).collect()
}

fn only<const N: usize>(names: [&str; N]) -> FieldSet {
    FieldSet::Only { fields: set(names) }
}

#[test]
fn a_policy_without_fields_decides_as_before() {
    let e = engine(false);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")),
        editor(
            "nope",
            Effect::Deny,
            "document.edit",
            TargetSelector::exact("document", "d2"),
        ),
    ];
    assert!(can(&e, &grants, "document.edit", None));
    assert!(can(&e, &grants, "document.edit", Some("anything")));
    assert_eq!(fields(&e, &grants, "document.edit"), FieldSet::All);
    let denied = vec![view()];
    assert!(!can(&e, &denied, "document.edit", None));
    assert!(!can(&e, &denied, "document.edit", Some("title")));
    assert_eq!(fields(&e, &denied, "document.edit"), FieldSet::None);
    let decision = e.decide(&Context::new(&grants), &Request::new(&ana(), "document.edit", &doc()));
    assert!(matches!(decision.reason, Reason::Grant { ref grant_id, .. } if grant_id == "edit"));
}

#[test]
fn an_allow_with_fields_gives_only_those_fields() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")).fields(["title", "body"]),
    ];
    assert_eq!(fields(&e, &grants, "document.edit"), only(["title", "body"]));
    assert!(can(&e, &grants, "document.edit", Some("title")));
    assert!(!can(&e, &grants, "document.edit", Some("status")));
}

#[test]
fn a_field_restricted_allow_never_opens_the_whole_resource() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")).fields(["title"]),
    ];
    assert!(!can(&e, &grants, "document.edit", None));
}

#[test]
fn a_deny_with_fields_takes_away_only_those_fields() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project")).fields(["status"]),
    ];
    assert_eq!(fields(&e, &grants, "document.edit"), only(["title", "body"]));
    assert!(can(&e, &grants, "document.edit", Some("body")));
    assert!(!can(&e, &grants, "document.edit", Some("status")));
}

#[test]
fn a_deny_with_fields_blocks_the_whole_resource_question() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project")).fields(["status"]),
    ];
    let decision = e.decide(&Context::new(&grants), &Request::new(&ana(), "document.edit", &doc()));
    assert!(!decision.is_allowed());
    assert!(matches!(decision.reason, Reason::Grant { ref grant_id, .. } if grant_id == "lock"));
}

#[test]
fn a_deny_at_a_broader_step_does_not_block_a_closer_allow_under_most_specific() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor(
            "edit",
            Effect::Allow,
            "document.edit",
            TargetSelector::exact("document", "d1"),
        ),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project")).fields(["status"]),
    ];
    assert!(
        can(&e, &grants, "document.edit", Some("status")),
        "the closer allow wins for the field"
    );
    assert!(
        can(&e, &grants, "document.edit", None),
        "and then nothing blocks the whole resource"
    );
}

#[test]
fn without_declared_fields_the_rest_is_all_except_the_denied_ones() {
    let e = engine(false);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project")).fields(["status"]),
    ];
    let allowed = fields(&e, &grants, "document.edit");
    assert_eq!(
        allowed,
        FieldSet::AllExcept {
            fields: set(["status"])
        }
    );
    assert!(allowed.contains("title"));
    assert!(!allowed.contains("status"));
    assert!(can(&e, &grants, "document.edit", Some("never_heard_of")));
}

#[test]
fn without_declared_fields_a_restricted_allow_gives_a_list() {
    let e = engine(false);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")).fields(["title"]),
    ];
    assert_eq!(fields(&e, &grants, "document.edit"), only(["title"]));
    assert!(!can(&e, &grants, "document.edit", Some("never_heard_of")));
}

#[test]
fn a_field_the_catalog_does_not_declare_is_denied() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")),
    ];
    assert!(can(&e, &grants, "document.edit", Some("title")));
    assert!(!can(&e, &grants, "document.edit", Some("bogus")));
    assert_eq!(fields(&e, &grants, "document.edit"), FieldSet::All);
}

#[test]
fn deny_overrides_lets_a_field_deny_win_at_any_step() {
    let e = engine_with(true, DenyOverrides);
    let grants = vec![
        view(),
        editor(
            "edit",
            Effect::Allow,
            "document.edit",
            TargetSelector::exact("document", "d1"),
        ),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project")).fields(["body"]),
    ];
    assert_eq!(fields(&e, &grants, "document.edit"), only(["title", "status"]));
    assert!(!can(&e, &grants, "document.edit", None));
}

#[test]
fn permit_overrides_lets_a_field_allow_win_over_a_field_deny() {
    let e = engine_with(true, PermitOverrides);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")).fields(["body"]),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project")).fields(["body", "status"]),
    ];
    assert_eq!(fields(&e, &grants, "document.edit"), only(["body"]));
}

#[test]
fn first_applicable_decides_each_field_by_the_first_grant_that_covers_it() {
    let e = engine_with(true, FirstApplicable);
    let grants = vec![
        view(),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project")).fields(["status"]),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")),
    ];
    assert_eq!(fields(&e, &grants, "document.edit"), only(["title", "body"]));
}

#[test]
fn most_specific_decides_each_field_by_its_own_closest_step() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor("wide", Effect::Allow, "document.edit", TargetSelector::kind("project")),
        editor(
            "no-body",
            Effect::Deny,
            "document.edit",
            TargetSelector::kind("project"),
        )
        .fields(["body"]),
        editor(
            "body-here",
            Effect::Allow,
            "document.edit",
            TargetSelector::exact("document", "d1"),
        )
        .fields(["body"]),
    ];
    assert_eq!(fields(&e, &grants, "document.edit"), FieldSet::All);
}

#[test]
fn an_implying_grant_with_fields_gives_the_implied_permission_on_those_fields_only() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor(
            "manage",
            Effect::Allow,
            "document.manage",
            TargetSelector::kind("project"),
        )
        .fields(["title"]),
    ];
    assert_eq!(fields(&e, &grants, "document.edit"), only(["title"]));
    assert!(!can(&e, &grants, "document.edit", Some("body")));
}

#[test]
fn a_prerequisite_is_judged_on_the_same_field() {
    let e = engine(true);
    let grants = vec![
        editor("view", Effect::Allow, "document.view", TargetSelector::kind("project")).fields(["title"]),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")),
    ];
    assert_eq!(fields(&e, &grants, "document.edit"), only(["title"]));
    let decision = e.decide(
        &Context::new(&grants),
        &Request::new(&ana(), "document.edit", &doc()).field("body"),
    );
    assert!(!decision.is_allowed());
    assert!(matches!(decision.reason, Reason::MissingPrerequisite { .. }));
}

#[test]
fn a_condition_that_cannot_be_evaluated_never_opens_a_field() {
    let e = engine(true);
    let unknown = Condition::eq(Operand::attr("resource.owner"), Operand::lit("ana"));
    let allow = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project"))
            .fields(["title"])
            .when(unknown.clone()),
    ];
    assert_eq!(fields(&e, &allow, "document.edit"), FieldSet::None);

    let deny = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project"))
            .fields(["status"])
            .when(unknown),
    ];
    assert_eq!(fields(&e, &deny, "document.edit"), only(["title", "body"]));
}

#[test]
fn a_false_condition_leaves_the_field_alone() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")).fields(["title", "body"]),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project"))
            .fields(["body"])
            .when(Condition::eq(Operand::attr("resource.state"), Operand::lit("frozen"))),
    ];
    let open = Resource::new("document", "d1")
        .within("project", "p1")
        .with_attr("state", "draft");
    let frozen = Resource::new("document", "d1")
        .within("project", "p1")
        .with_attr("state", "frozen");
    let ctx = Context::new(&grants);
    assert_eq!(
        e.allowed_fields(&ctx, &ana(), "document.edit", &open),
        only(["title", "body"])
    );
    assert_eq!(
        e.allowed_fields(&ctx, &ana(), "document.edit", &frozen),
        only(["title"])
    );
}

#[test]
fn an_unknown_permission_has_no_fields() {
    let e = engine(true);
    assert_eq!(fields(&e, &[view()], "document.nope"), FieldSet::None);
}

#[test]
fn explain_fields_names_the_grants_that_gave_and_took_each_field() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project")).fields(["status"]),
    ];
    let explanation = e.explain_fields(&Context::new(&grants), &ana(), "document.edit", &doc());
    assert_eq!(explanation.allowed, only(["title", "body"]));
    let status = explanation
        .fields
        .iter()
        .find(|f| f.field.as_deref() == Some("status"))
        .unwrap();
    assert!(!status.allowed);
    assert_eq!(status.granted_by, ["edit"]);
    assert_eq!(status.denied_by, ["lock"]);
    let title = explanation
        .fields
        .iter()
        .find(|f| f.field.as_deref() == Some("title"))
        .unwrap();
    assert!(title.allowed);
    assert_eq!(title.granted_by, ["edit"]);
    assert!(title.denied_by.is_empty());
}

#[test]
fn explain_of_a_field_request_marks_the_grants_that_do_not_cover_it() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")).fields(["title"]),
    ];
    let explanation = e.explain(
        &Context::new(&grants),
        &Request::new(&ana(), "document.edit", &doc()).field("body"),
    );
    assert_eq!(explanation.field.as_deref(), Some("body"));
    let trace = explanation.grants.iter().find(|g| g.grant.id == "edit").unwrap();
    assert_eq!(trace.verdict, strig::Verdict::FieldNotCovered);
    assert!(!explanation.decision.is_allowed());
}

#[test]
fn an_override_that_allows_gives_every_field() {
    let engine = Engine::builder(catalog(true))
        .override_with(strig::ResourceOwner::new("owner"))
        .build()
        .unwrap();
    let mine = Resource::new("document", "d1")
        .within("project", "p1")
        .with_attr("owner", "ana");
    let ctx_grants: Vec<Grant> = Vec::new();
    let ctx = Context::new(&ctx_grants);
    assert_eq!(
        engine.allowed_fields(&ctx, &ana(), "document.edit", &mine),
        FieldSet::All
    );
    assert!(
        engine
            .explain_fields(&ctx, &ana(), "document.edit", &mine)
            .overridden_by
            .is_some()
    );
}

#[test]
fn validate_grant_refuses_a_field_the_catalog_does_not_declare() {
    let e = engine(true);
    let ok = editor("g", Effect::Allow, "document.edit", TargetSelector::kind("project")).fields(["title"]);
    assert_eq!(e.validate_grant(&ok), Ok(()));
    let bad = editor("g", Effect::Allow, "document.edit", TargetSelector::kind("project")).fields(["titel"]);
    assert_eq!(
        e.validate_grant(&bad),
        Err(GrantError::UnknownField {
            permission: "document.edit".into(),
            field: "titel".into()
        })
    );
    let weird = editor("g", Effect::Allow, "document.edit", TargetSelector::kind("project")).fields(["a b"]);
    assert_eq!(e.validate_grant(&weird), Err(GrantError::InvalidField("a b".into())));
    let free = engine(false);
    assert_eq!(
        free.validate_grant(&bad),
        Ok(()),
        "an undeclared catalog trusts the grant"
    );
}

#[test]
fn the_catalog_refuses_a_bad_or_repeated_field() {
    let build = |fields: [&str; 2]| {
        Catalog::builder()
            .target_kinds(["document"])
            .permission(PermissionDef::new("document.edit").targets(["document"]).fields(fields))
            .build()
    };
    assert!(build(["title", "address.street"]).is_ok());
    assert!(build(["title", "9lives"]).is_err());
    assert!(build(["title", "title"]).is_err());
}

#[test]
fn a_grant_without_fields_serializes_as_it_always_did() {
    let grant = editor("g", Effect::Allow, "document.edit", TargetSelector::kind("project"));
    let json = serde_json::to_value(&grant).unwrap();
    assert!(json.get("fields").is_none());
    let with = serde_json::to_value(grant.fields(["title"])).unwrap();
    assert_eq!(with["fields"], serde_json::json!(["title"]));
}

#[test]
fn capabilities_with_fields_carry_the_real_grants_next_to_a_safe_form_for_older_readers() {
    let e = engine(true);
    let grants = vec![
        view(),
        editor("edit", Effect::Allow, "document.edit", TargetSelector::kind("project")).fields(["title"]),
        editor("lock", Effect::Deny, "document.edit", TargetSelector::kind("project")).fields(["status"]),
    ];
    let set = e.capabilities(&Context::new(&grants), &ana(), &doc());
    let wire = serde_json::to_value(&set).unwrap();
    let old: Vec<&str> = wire["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        old,
        ["view", "lock"],
        "an older reader sees no restricted allow, and the deny whole"
    );
    assert!(wire["grants"][1].get("fields").is_none());
    assert_eq!(wire["withFields"].as_array().unwrap().len(), 3);
    let back: strig::CapabilitySet = serde_json::from_value(wire).unwrap();
    assert_eq!(back, set);
    assert_eq!(
        e.allowed_fields(&Context::new(&back), &ana(), "document.edit", &doc()),
        only(["title"])
    );
}

#[test]
fn capabilities_without_fields_are_written_as_before() {
    let e = engine(true);
    let grants = vec![view()];
    let wire = serde_json::to_value(e.capabilities(&Context::new(&grants), &ana(), &doc())).unwrap();
    assert!(wire.get("withFields").is_none());
}
