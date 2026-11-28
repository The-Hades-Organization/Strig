//! `Engine::why_not`: the smallest verified changes that would turn a denial into an `allow`.

use strig::{
    Catalog, Cause, Caveat, Change, Condition, Context, Effect, Engine, Grant, Operand, PermissionDef, QueryLimits,
    Remedies, Request, Resource, Subject, SubjectMatcher, TargetSelector, WhyNotOptions,
};

fn catalog() -> Catalog {
    Catalog::builder()
        .target_kinds(["document", "project"])
        .permission(PermissionDef::new("document.view").targets(["document", "project"]))
        .permission(
            PermissionDef::new("document.edit")
                .targets(["document", "project"])
                .depends_on(["document.view"])
                .fields(["title", "body"]),
        )
        .permission(
            PermissionDef::new("document.admin")
                .targets(["document", "project"])
                .management_only()
                .non_delegable(),
        )
        .permission(
            PermissionDef::new("document.root")
                .targets(["document"])
                .override_only(),
        )
        .build()
        .expect("catalog")
}

fn engine() -> Engine {
    Engine::builder(catalog()).build().expect("engine")
}

fn doc() -> Resource {
    Resource::new("document", "d1").within("project", "p1")
}

fn ana() -> Subject {
    Subject::user("ana")
}

fn role_allow(id: &str, role: &str, permission: &str, target: TargetSelector) -> Grant {
    Grant::allow(id, SubjectMatcher::role(role), permission, target)
}

fn ask(
    engine: &Engine,
    grants: &[Grant],
    subject: &Subject,
    permission: &str,
    field: Option<&str>,
) -> Option<Remedies> {
    ask_with(
        engine,
        grants,
        subject,
        permission,
        field,
        &WhyNotOptions::default(),
        None,
    )
}

fn ask_with(
    engine: &Engine,
    grants: &[Grant],
    subject: &Subject,
    permission: &str,
    field: Option<&str>,
    options: &WhyNotOptions,
    now: Option<u64>,
) -> Option<Remedies> {
    let resource = doc();
    let mut request = Request::new(subject, permission, &resource);
    if let Some(field) = field {
        request = request.field(field);
    }
    let ctx = Context::new(&grants);
    let ctx = now.map_or(ctx, |now| ctx.at(now));
    engine.why_not(&ctx, &request, options)
}

fn changes(answer: &Remedies) -> Vec<&Change> {
    answer.remedies.iter().map(|r| &r.change).collect()
}

fn decide_with(engine: &Engine, grants: &[Grant], subject: &Subject, permission: &str, change: &Change) -> bool {
    let resource = doc();
    let mut grants = grants.to_vec();
    let mut subject = subject.clone();
    match change {
        Change::AssignRole { role, scope } => match scope {
            Some(scope) => subject = subject.with_role_in(role.clone(), scope.clone()),
            None => subject = subject.with_role(role.clone()),
        },
        Change::AddGrant { grant } => grants.push((**grant).clone()),
        Change::RemoveDeny { grant_id, .. } => grants.retain(|g| &g.id != grant_id),
        _ => unreachable!("not applied by hand"),
    }
    engine
        .decide(&Context::new(&grants), &Request::new(&subject, permission, &resource))
        .is_allowed()
}

#[test]
fn an_allowed_request_has_nothing_to_explain() {
    let grants = [Grant::allow(
        "g",
        SubjectMatcher::user("ana"),
        "document.view",
        TargetSelector::kind("project"),
    )];
    assert!(ask(&engine(), &grants, &ana(), "document.view", None).is_none());
}

#[test]
fn suggests_a_grant_on_the_most_specific_step_before_a_role() {
    let engine = engine();
    let grants = [role_allow(
        "r",
        "viewer",
        "document.view",
        TargetSelector::kind("project"),
    )];
    let answer = ask(&engine, &grants, &ana(), "document.view", None).expect("denied");
    assert_eq!(answer.cause, Cause::NoApplicableGrant);
    assert!(!answer.partial);

    let [
        Change::AddGrant { grant: exact },
        Change::AddGrant { grant: kind },
        Change::AssignRole { role, scope },
    ] = changes(&answer)[..]
    else {
        panic!("unexpected remedies: {:?}", answer.remedies);
    };
    assert_eq!(exact.target, TargetSelector::exact("document", "d1"));
    assert_eq!(kind.target, TargetSelector::kind("document"));
    assert_eq!(exact.subject, SubjectMatcher::user("ana"));
    assert_eq!(role, "viewer");
    assert_eq!(scope.as_ref().map(ToString::to_string).as_deref(), Some("document:d1"));
    assert_eq!(answer.remedies[0].rank, Some(0));
}

#[test]
fn every_remedy_really_turns_the_decision_into_allow() {
    let engine = engine();
    let grants = [role_allow(
        "r",
        "viewer",
        "document.view",
        TargetSelector::kind("project"),
    )];
    let answer = ask(&engine, &grants, &ana(), "document.view", None).expect("denied");
    assert!(!answer.remedies.is_empty());
    for remedy in &answer.remedies {
        assert!(
            decide_with(&engine, &grants, &ana(), "document.view", &remedy.change),
            "{:?} did not allow",
            remedy.change
        );
    }
}

#[test]
fn a_role_that_cannot_help_is_not_suggested() {
    let engine = engine();
    let grants = [
        role_allow("r", "viewer", "document.view", TargetSelector::kind("project")),
        Grant::deny(
            "d",
            SubjectMatcher::Any,
            "document.view",
            TargetSelector::exact("document", "d1"),
        ),
    ];
    let answer = ask(&engine, &grants, &ana(), "document.view", None).expect("denied");
    assert!(matches!(answer.cause, Cause::Deny { ref grant_id, .. } if grant_id == "d"));
    assert!(
        !changes(&answer)
            .iter()
            .any(|c| matches!(c, Change::AssignRole { .. } | Change::AddGrant { .. })),
        "{:?}",
        answer.remedies
    );
}

#[test]
fn the_deciding_deny_is_named_and_marked_when_it_is_shared() {
    let engine = engine();
    let grants = [
        Grant::allow(
            "a",
            SubjectMatcher::user("ana"),
            "document.view",
            TargetSelector::kind("project"),
        ),
        Grant::deny(
            "d",
            SubjectMatcher::Any,
            "document.view",
            TargetSelector::exact("document", "d1"),
        ),
    ];
    let answer = ask(&engine, &grants, &ana(), "document.view", None).expect("denied");
    let Cause::Deny { grant_id, target, .. } = &answer.cause else {
        panic!("{:?}", answer.cause);
    };
    assert_eq!(grant_id, "d");
    assert_eq!(*target, TargetSelector::exact("document", "d1"));
    let [remedy] = &answer.remedies[..] else {
        panic!("{:?}", answer.remedies);
    };
    assert!(matches!(&remedy.change, Change::RemoveDeny { grant_id, .. } if grant_id == "d"));
    assert_eq!(remedy.caveats, [Caveat::AffectsOthers]);
}

#[test]
fn the_subjects_own_deny_is_not_marked_as_shared() {
    let engine = engine();
    let grants = [
        Grant::allow(
            "a",
            SubjectMatcher::user("ana"),
            "document.view",
            TargetSelector::kind("project"),
        ),
        Grant::deny(
            "d",
            SubjectMatcher::user("ana"),
            "document.view",
            TargetSelector::kind("document"),
        ),
    ];
    let answer = ask(&engine, &grants, &ana(), "document.view", None).expect("denied");
    assert!(answer.remedies[0].caveats.is_empty());
}

#[test]
fn grants_of_other_subjects_never_show_up() {
    let engine = engine();
    let grants = [
        Grant::allow(
            "bob-allow",
            SubjectMatcher::user("bob"),
            "document.view",
            TargetSelector::kind("project"),
        ),
        Grant::deny(
            "bob-deny",
            SubjectMatcher::user("bob"),
            "document.view",
            TargetSelector::kind("project"),
        ),
    ];
    let answer = ask(&engine, &grants, &ana(), "document.view", None).expect("denied");
    let json = serde_json::to_string(&answer).unwrap();
    assert!(!json.contains("bob"), "{json}");
}

#[test]
fn a_false_condition_is_named_without_inventing_a_value() {
    let engine = engine();
    let grants = [Grant::allow(
        "g",
        SubjectMatcher::user("ana"),
        "document.view",
        TargetSelector::kind("project"),
    )
    .when(Condition::eq(Operand::attr("subject.plan"), Operand::lit("pro")))];
    let subject = ana().with_attr("plan", "free");
    let answer = ask(&engine, &grants, &subject, "document.view", None).expect("denied");
    let Some(Change::SatisfyCondition {
        grant_id,
        failed,
        unresolved,
    }) = changes(&answer)
        .into_iter()
        .find(|c| matches!(c, Change::SatisfyCondition { .. }))
        .cloned()
    else {
        panic!("{:?}", answer.remedies);
    };
    assert_eq!(grant_id, "g");
    assert_eq!(failed, [r#"subject.plan ("free") = "pro""#]);
    assert!(unresolved.is_empty());
    assert!(
        matches!(answer.remedies[0].change, Change::SatisfyCondition { .. }),
        "first, it changes no policy"
    );
}

#[test]
fn a_time_window_outside_is_reported_as_the_failed_condition() {
    let engine = engine();
    let grants = [Grant::allow(
        "g",
        SubjectMatcher::user("ana"),
        "document.view",
        TargetSelector::kind("project"),
    )
    .when(Condition::time_between("09:00", "17:00"))];
    let at_three_am = 1_704_078_000_000;
    let answer = ask_with(
        &engine,
        &grants,
        &ana(),
        "document.view",
        None,
        &WhyNotOptions::default(),
        Some(at_three_am),
    )
    .expect("denied");
    let Change::SatisfyCondition { failed, .. } = &answer.remedies[0].change else {
        panic!("{:?}", answer.remedies);
    };
    assert_eq!(failed.len(), 1);
    assert!(failed[0].starts_with("hora "), "{failed:?}");
}

#[test]
fn a_missing_attribute_is_unresolved_not_invented() {
    let engine = engine();
    let grants = [Grant::allow(
        "g",
        SubjectMatcher::user("ana"),
        "document.view",
        TargetSelector::kind("project"),
    )
    .when(Condition::eq(Operand::attr("subject.ip_zone"), Operand::lit("office")))];
    let answer = ask(&engine, &grants, &ana(), "document.view", None).expect("denied");
    let remedy = answer
        .remedies
        .iter()
        .find_map(|r| match &r.change {
            Change::SatisfyCondition { unresolved, failed, .. } => Some((unresolved, failed)),
            _ => None,
        })
        .expect("condition remedy");
    assert!(remedy.1.is_empty());
    assert_eq!(remedy.0.len(), 1);
    assert!(remedy.0[0].starts_with("subject.ip_zone"), "{:?}", remedy.0);
}

#[test]
fn an_override_is_named_and_offers_no_remedy() {
    let engine = Engine::builder(catalog())
        .override_with(strig::FnOverride::new("suspended", |_: &Request<'_>| {
            Some(Effect::Deny)
        }))
        .build()
        .expect("engine");
    let grants = [role_allow(
        "r",
        "viewer",
        "document.view",
        TargetSelector::kind("project"),
    )];
    let answer = ask(&engine, &grants, &ana().with_role("viewer"), "document.view", None).expect("denied");
    assert_eq!(
        answer.cause,
        Cause::Override {
            name: "suspended".into()
        }
    );
    assert!(answer.remedies.is_empty());
    assert!(!answer.partial);
}

#[test]
fn an_unknown_permission_fails_closed_with_no_remedy() {
    let answer = ask(&engine(), &[], &ana(), "document.nope", None).expect("denied");
    assert_eq!(answer.cause, Cause::UnknownPermission);
    assert!(answer.remedies.is_empty());
}

#[test]
fn an_override_only_permission_is_named_and_offers_no_remedy() {
    let answer = ask(&engine(), &[], &ana(), "document.root", None).expect("denied");
    assert_eq!(answer.cause, Cause::OverrideOnlyPermission);
    assert!(answer.remedies.is_empty());
}

#[test]
fn governance_flags_of_the_catalog_mark_the_remedy() {
    let engine = engine();
    let answer = ask(&engine, &[], &ana(), "document.admin", None).expect("denied");
    assert!(!answer.remedies.is_empty());
    for remedy in &answer.remedies {
        assert_eq!(
            remedy.caveats,
            [Caveat::ManagementOnly, Caveat::NonDelegable],
            "{remedy:?}"
        );
    }
}

#[test]
fn a_field_question_asks_for_a_grant_on_that_field_only() {
    let engine = engine();
    let answer = ask(&engine, &[], &ana(), "document.edit", Some("title")).expect("denied");
    let grants: Vec<_> = answer
        .remedies
        .iter()
        .filter_map(|r| match &r.change {
            Change::AddGrant { grant } => Some(grant),
            _ => None,
        })
        .collect();
    assert!(grants.iter().all(|g| g.fields == ["title"]), "{:?}", answer.remedies);
    assert!(grants.is_empty() || grants[0].permission == "document.edit");
}

#[test]
fn a_deny_on_fields_is_narrowed_to_leave_the_asked_field_out() {
    let engine = engine();
    let grants = [
        Grant::allow(
            "a",
            SubjectMatcher::user("ana"),
            "document.edit",
            TargetSelector::kind("project"),
        ),
        Grant::allow(
            "v",
            SubjectMatcher::user("ana"),
            "document.view",
            TargetSelector::kind("project"),
        ),
        Grant::deny(
            "d",
            SubjectMatcher::user("ana"),
            "document.edit",
            TargetSelector::exact("document", "d1"),
        )
        .fields(["title", "body"]),
    ];
    let answer = ask(&engine, &grants, &ana(), "document.edit", Some("title")).expect("denied");
    assert!(
        answer.remedies.iter().any(
            |r| matches!(&r.change, Change::NarrowDeny { grant_id, field } if grant_id == "d" && field == "title")
        ),
        "{:?}",
        answer.remedies
    );
    let narrow = answer
        .remedies
        .iter()
        .position(|r| matches!(r.change, Change::NarrowDeny { .. }))
        .unwrap();
    let remove = answer
        .remedies
        .iter()
        .position(|r| matches!(r.change, Change::RemoveDeny { .. }))
        .unwrap();
    assert!(narrow < remove, "narrowing is smaller than removing");
}

#[test]
fn a_missing_prerequisite_is_named_and_the_remedy_is_for_the_prerequisite() {
    let engine = engine();
    let grants = [Grant::allow(
        "e",
        SubjectMatcher::user("ana"),
        "document.edit",
        TargetSelector::kind("project"),
    )];
    let answer = ask(&engine, &grants, &ana(), "document.edit", None).expect("denied");
    assert_eq!(
        answer.cause,
        Cause::MissingPrerequisite {
            prerequisite: "document.view".into(),
            cause: Box::new(Cause::NoApplicableGrant),
        }
    );
    let Some(Change::AddGrant { grant }) = answer.remedies.first().map(|r| &r.change) else {
        panic!("{:?}", answer.remedies);
    };
    assert_eq!(grant.permission, "document.view");
}

#[test]
fn the_verification_budget_marks_the_answer_partial() {
    let engine = engine();
    let grants = [role_allow(
        "r",
        "viewer",
        "document.view",
        TargetSelector::kind("project"),
    )];
    let options = WhyNotOptions::default().with_limits(QueryLimits::default().with_max_decisions(1));
    let answer = ask_with(&engine, &grants, &ana(), "document.view", None, &options, None).expect("denied");
    assert!(answer.partial);
    assert!(answer.remedies.len() <= 1);

    let none = WhyNotOptions::default().with_limits(QueryLimits::default().with_max_decisions(0));
    let answer = ask_with(&engine, &grants, &ana(), "document.view", None, &none, None).expect("denied");
    assert!(answer.partial && answer.remedies.is_empty());
}

#[test]
fn max_remedies_cuts_the_list_and_marks_it_partial() {
    let engine = engine();
    let grants = [role_allow(
        "r",
        "viewer",
        "document.view",
        TargetSelector::kind("project"),
    )];
    let options = WhyNotOptions::default().with_max_remedies(2);
    let answer = ask_with(&engine, &grants, &ana(), "document.view", None, &options, None).expect("denied");
    assert_eq!(answer.remedies.len(), 2);
    assert!(answer.partial);
}

#[test]
fn the_answer_round_trips_through_json() {
    let engine = engine();
    let grants = [role_allow(
        "r",
        "viewer",
        "document.view",
        TargetSelector::kind("project"),
    )];
    let answer = ask(&engine, &grants, &ana(), "document.view", None).expect("denied");
    let json = serde_json::to_value(&answer).unwrap();
    assert_eq!(json["cause"]["kind"], "no_applicable_grant");
    assert_eq!(json["remedies"][0]["kind"], "add_grant");
    let back: Remedies = serde_json::from_value(json).unwrap();
    assert_eq!(back, answer);
}
