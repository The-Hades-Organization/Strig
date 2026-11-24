//! Validity windows: exact edges, missing `now`, expired inherited roles, explanations,
//! capabilities and serialization compatibility.

mod support;

use strig::{
    Context, Engine, Grant, GrantError, Request, RoleAssignment, RoleGraph, Subject, SubjectMatcher, TargetSelector,
    ValidityError, Verdict, next_boundary,
};
use support::*;

const FROM: u64 = 1_000;
const UNTIL: u64 = 2_000;

fn viewer() -> Subject {
    Subject::user("u1").with_role_in("member", org())
}

fn allowed(grants: &[Grant], subject: &Subject, now: Option<u64>) -> bool {
    let ctx = Context::new(&grants);
    let ctx = now.map_or(ctx, |now| ctx.at(now));
    engine().check(&ctx, &Request::new(subject, "project.view", &project()))
}

fn windowed_allow() -> Vec<Grant> {
    vec![role_grant("g", "member", "project.view", true, at_org()).valid_between(FROM, UNTIL)]
}

#[test]
fn grant_start_is_inclusive_and_end_is_exclusive() {
    let grants = windowed_allow();
    assert!(!allowed(&grants, &viewer(), Some(FROM - 1)));
    assert!(allowed(&grants, &viewer(), Some(FROM)));
    assert!(allowed(&grants, &viewer(), Some(UNTIL - 1)));
    assert!(!allowed(&grants, &viewer(), Some(UNTIL)));
}

#[test]
fn open_ended_grants_follow_the_present_bound_only() {
    let from_only = vec![role_grant("g", "member", "project.view", true, at_org()).valid_from(FROM)];
    assert!(!allowed(&from_only, &viewer(), Some(FROM - 1)));
    assert!(allowed(&from_only, &viewer(), Some(u64::MAX)));
    let until_only = vec![role_grant("g", "member", "project.view", true, at_org()).valid_until(UNTIL)];
    assert!(allowed(&until_only, &viewer(), Some(0)));
    assert!(!allowed(&until_only, &viewer(), Some(UNTIL)));
}

#[test]
fn without_now_an_allow_with_a_window_is_ignored() {
    assert!(!allowed(&windowed_allow(), &viewer(), None));
}

#[test]
fn without_now_a_grant_with_no_window_still_applies() {
    let grants = vec![role_grant("g", "member", "project.view", true, at_org())];
    assert!(allowed(&grants, &viewer(), None));
}

#[test]
fn without_now_a_deny_with_a_window_still_holds() {
    let grants = vec![
        role_grant("a", "member", "project.view", true, at_org()),
        role_grant("d", "member", "project.view", false, at_org()).valid_between(FROM, UNTIL),
    ];
    assert!(!allowed(&grants, &viewer(), None));
    assert!(!allowed(&grants, &viewer(), Some(FROM)));
    assert!(allowed(&grants, &viewer(), Some(UNTIL)));
}

#[test]
fn expired_role_is_gone_for_the_decision() {
    let grants = vec![role_grant("g", "member", "project.view", true, at_org())];
    let temporary =
        Subject::user("u1").with_assignment(RoleAssignment::in_scope("member", org()).valid_between(FROM, UNTIL));
    assert!(!allowed(&grants, &temporary, Some(FROM - 1)));
    assert!(allowed(&grants, &temporary, Some(FROM)));
    assert!(!allowed(&grants, &temporary, Some(UNTIL)));
    assert!(!allowed(&grants, &temporary, None));
}

#[test]
fn expired_role_is_gone_for_the_roles_that_inherit_from_it() {
    let roles = RoleGraph::builder().inherit("lead", "member").build().unwrap();
    let engine = Engine::builder(catalog()).roles(roles).build().unwrap();
    let grants = vec![role_grant("g", "member", "project.view", true, at_org())];
    let lead = Subject::user("u1").with_assignment(RoleAssignment::in_scope("lead", org()).valid_until(UNTIL));
    let check = |now| {
        engine.check(
            &Context::new(&grants).at(now),
            &Request::new(&lead, "project.view", &project()),
        )
    };
    assert!(check(UNTIL - 1));
    assert!(!check(UNTIL));
}

#[test]
fn deny_keyed_on_a_role_with_a_window_holds_when_now_is_missing() {
    let grants = vec![
        Grant::allow("a", SubjectMatcher::user("u1"), "project.view", at_org()),
        role_grant("d", "suspended", "project.view", false, at_org()),
    ];
    let subject =
        Subject::user("u1").with_assignment(RoleAssignment::in_scope("suspended", org()).valid_between(FROM, UNTIL));
    assert!(!allowed(&grants, &subject, None));
    assert!(!allowed(&grants, &subject, Some(FROM)));
    assert!(allowed(&grants, &subject, Some(UNTIL)));
}

#[test]
fn explanation_names_the_window_as_the_reason() {
    let grants = windowed_allow();
    let ctx = Context::new(&grants).at(UNTIL);
    let viewer = viewer();
    let explanation = engine().explain(&ctx, &Request::new(&viewer, "project.view", &project()));
    assert!(!explanation.decision.is_allowed());
    assert_eq!(explanation.grants[0].verdict, Verdict::OutsideWindow);
    let inside = engine().explain(
        &Context::new(&grants).at(FROM),
        &Request::new(&viewer, "project.view", &project()),
    );
    assert!(inside.decision.is_allowed());
    assert_eq!(inside.grants[0].verdict, Verdict::Candidate);
}

#[test]
fn explanation_drops_expired_roles_from_the_resolved_roles() {
    let grants: Vec<Grant> = Vec::new();
    let subject = Subject::user("u1").with_assignment(RoleAssignment::in_scope("member", org()).valid_until(UNTIL));
    let request = |now| {
        engine()
            .explain(
                &Context::new(&grants).at(now),
                &Request::new(&subject, "project.view", &project()),
            )
            .roles
    };
    assert_eq!(request(UNTIL - 1), ["member"]);
    assert!(request(UNTIL).is_empty());
}

#[test]
fn capabilities_leave_out_grants_outside_the_window() {
    let grants = windowed_allow();
    let capabilities = |now| engine().capabilities(&Context::new(&grants).at(now), &viewer(), &project());
    assert!(capabilities(FROM - 1).grants.is_empty());
    assert_eq!(capabilities(FROM).grants.len(), 1);
    assert!(capabilities(UNTIL).grants.is_empty());
}

#[test]
fn capabilities_decide_like_the_source_they_came_from() {
    let grants = windowed_allow();
    let set = engine().capabilities(&Context::new(&grants).at(FROM), &viewer(), &project());
    let viewer = viewer();
    let resource = project();
    let request = Request::new(&viewer, "project.view", &resource);
    assert!(engine().check(&Context::new(&set).at(FROM), &request));
    assert!(!engine().check(&Context::new(&set).at(UNTIL), &request));
}

#[test]
fn next_boundary_covers_grants_and_roles() {
    let grants = windowed_allow();
    let subject = Subject::user("u1").with_assignment(RoleAssignment::new("member").valid_between(500, 1_500));
    assert_eq!(next_boundary(0, &grants, &subject.roles), Some(500));
    assert_eq!(next_boundary(500, &grants, &subject.roles), Some(FROM));
    assert_eq!(next_boundary(FROM, &grants, &subject.roles), Some(1_500));
    assert_eq!(next_boundary(1_500, &grants, &subject.roles), Some(UNTIL));
    assert_eq!(next_boundary(UNTIL, &grants, &subject.roles), None);
}

#[test]
fn capability_set_reports_its_next_boundary() {
    let grants = windowed_allow();
    let set = engine().capabilities(&Context::new(&grants).at(FROM), &viewer(), &project());
    assert_eq!(set.next_boundary(FROM), Some(UNTIL));
    assert_eq!(set.next_boundary(UNTIL), None);
}

#[test]
fn inverted_window_is_refused_when_the_grant_is_validated() {
    let grant = role_grant("g", "member", "project.view", true, at_org()).valid_between(UNTIL, FROM);
    assert_eq!(
        engine().validate_grant(&grant),
        Err(GrantError::InvalidWindow(ValidityError::Inverted {
            from: UNTIL,
            until: FROM
        }))
    );
    assert!(engine().validate_grant(&windowed_allow()[0]).is_ok());
}

#[test]
fn builders_refuse_an_inverted_or_empty_window() {
    let grant = || Grant::allow("g", SubjectMatcher::Any, "project.view", TargetSelector::global());
    assert!(grant().try_valid_between(UNTIL, FROM).is_err());
    assert!(grant().try_valid_between(FROM, FROM).is_err());
    assert_eq!(
        grant().try_valid_between(FROM, UNTIL).unwrap().validity().valid_until,
        Some(UNTIL)
    );
    assert!(
        RoleAssignment::new("r")
            .valid_between(UNTIL, FROM)
            .check_window()
            .is_err()
    );
    assert!(
        RoleAssignment::new("r")
            .valid_between(FROM, UNTIL)
            .check_window()
            .is_ok()
    );
}

#[test]
fn json_without_a_window_still_deserializes_and_stays_unchanged() {
    let json =
        r#"{"id":"g","subject":{"kind":"any"},"permission":"project.view","target":{"kind":"org"},"effect":"allow"}"#;
    let grant: Grant = serde_json::from_str(json).unwrap();
    assert_eq!(grant.validity().valid_from, None);
    assert_eq!(serde_json::to_string(&grant).unwrap(), json);

    let role: RoleAssignment = serde_json::from_str(r#"{"role":"member"}"#).unwrap();
    assert!(role.validity().is_unbounded());
    assert_eq!(serde_json::to_string(&role).unwrap(), r#"{"role":"member"}"#);
}

#[test]
fn window_round_trips_through_json() {
    let grant = windowed_allow().remove(0);
    let json = serde_json::to_string(&grant).unwrap();
    assert!(json.contains(r#""validFrom":1000"#) && json.contains(r#""validUntil":2000"#));
    assert_eq!(serde_json::from_str::<Grant>(&json).unwrap(), grant);
    let role = RoleAssignment::new("member").valid_between(FROM, UNTIL);
    let json = serde_json::to_string(&role).unwrap();
    assert!(json.contains(r#""valid_from":1000"#));
    assert_eq!(serde_json::from_str::<RoleAssignment>(&json).unwrap(), role);
}
