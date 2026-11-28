//! Policy tests: the runner over the example project and over small policies that break on purpose.

use strig::dsl::testing::{Outcome, TestFile, run};
use strig::dsl::{Policy, parse};

const POLICY: &str = "\
language blocks

target_kinds = [doc]

permission doc.read {
  targets = [doc]
}

role reader {
}

subject user:ana {
  assign reader {
  }
}

grant reader-reads {
  effect = allow
  subject = role reader
  permission = doc.read
  target = doc
}

invariant no_self_management {
}
";

fn policy() -> Policy {
    parse("policy.strig", POLICY).expect("the policy must parse").policy
}

fn tests(json: &str) -> TestFile {
    TestFile::parse("t.strig-test.json", json).unwrap_or_else(|e| panic!("{e}"))
}

fn single(json: &str) -> strig::dsl::testing::CaseResult {
    let report = run(&policy(), &[tests(json)]);
    assert_eq!(report.results.len(), 1, "{report:?}");
    report.results.into_iter().next().unwrap()
}

#[test]
fn a_case_that_matches_passes() {
    let result = single(
        r#"{"cases": [{"kind": "check", "subject": "user:ana", "permission": "doc.read",
            "resource": "doc:1", "expect": "allow", "grant": "reader-reads"}]}"#,
    );
    assert_eq!(result.outcome, Outcome::Passed, "{result:?}");
    assert_eq!(result.name, "case 1");
    assert!(result.explanation.is_none());
}

#[test]
fn a_case_that_differs_fails_with_the_diff_and_the_explanation() {
    let result = single(
        r#"{"cases": [{"kind": "check", "name": "wrong", "subject": "user:ana", "permission": "doc.read",
            "resource": "doc:1", "expect": "deny"}]}"#,
    );
    assert_eq!(result.outcome, Outcome::Failed);
    assert_eq!(result.expected, "deny");
    assert_eq!(result.actual, "allow, reason grant, decided by grant `reader-reads`");
    assert_eq!(result.trace, ["grant `reader-reads` (allow doc.read): candidate"]);
    assert_eq!(result.explanation.unwrap().decision.matched, ["reader-reads"]);
}

#[test]
fn the_wrong_decisive_grant_or_reason_fails_even_with_the_right_effect() {
    let by_grant = single(
        r#"{"cases": [{"kind": "check", "subject": "user:ana", "permission": "doc.read",
            "resource": "doc:1", "expect": "allow", "grant": "other"}]}"#,
    );
    assert_eq!(by_grant.outcome, Outcome::Failed);
    let by_reason = single(
        r#"{"cases": [{"kind": "check", "subject": "user:ana", "permission": "doc.read",
            "resource": "doc:1", "expect": "allow", "reason": "override"}]}"#,
    );
    assert_eq!(by_reason.outcome, Outcome::Failed);
}

#[test]
fn a_permission_outside_the_catalog_is_an_error_not_a_pass() {
    let result = single(
        r#"{"cases": [{"kind": "check", "subject": "user:ana", "permission": "doc.raed",
            "resource": "doc:1", "expect": "deny"}]}"#,
    );
    assert_eq!(result.outcome, Outcome::Errored);
    assert!(result.actual.contains("doc.raed"), "{}", result.actual);
}

#[test]
fn an_unknown_permission_can_be_expected_on_purpose() {
    let result = single(
        r#"{"cases": [{"kind": "check", "subject": "user:ana", "permission": "doc.gone",
            "resource": "doc:1", "expect": "deny", "reason": "unknown_permission"}]}"#,
    );
    assert_eq!(result.outcome, Outcome::Passed, "{result:?}");
}

#[test]
fn an_unknown_subject_or_a_bad_resource_is_an_error() {
    let subject = single(
        r#"{"cases": [{"kind": "check", "subject": "user:nobody", "permission": "doc.read",
            "resource": "doc:1", "expect": "deny"}]}"#,
    );
    assert_eq!(subject.outcome, Outcome::Errored);
    let resource = single(
        r#"{"cases": [{"kind": "check", "subject": "user:ana", "permission": "doc.read",
            "resource": "doc", "expect": "deny"}]}"#,
    );
    assert_eq!(resource.outcome, Outcome::Errored);
}

#[test]
fn a_fixture_grant_that_does_not_validate_errors_the_whole_file() {
    let report = run(
        &policy(),
        &[tests(
            r#"{"fixture": {"grants": [{"id": "g", "subject": {"kind": "any"}, "permission": "doc.nope",
                "target": {"kind": "doc"}, "effect": "allow"}]},
               "cases": [{"kind": "check", "subject": "user:ana", "permission": "doc.read",
                "resource": "doc:1", "expect": "allow"}]}"#,
        )],
    );
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].outcome, Outcome::Errored);
    assert_eq!(report.results[0].name, "(fixture)");
    assert!(!report.is_success());
}

#[test]
fn a_fixture_grant_may_not_reuse_a_policy_grant_id() {
    let report = run(
        &policy(),
        &[tests(
            r#"{"fixture": {"grants": [{"id": "reader-reads", "subject": {"kind": "any"}, "permission": "doc.read",
                "target": {"kind": "doc"}, "effect": "deny"}]}, "cases": []}"#,
        )],
    );
    assert_eq!(report.results[0].outcome, Outcome::Errored);
}

#[test]
fn a_fixture_adds_grants_subjects_and_env() {
    let result = single(
        r#"{"fixture": {"subjects": [{"kind": "user", "id": "bia", "attrs": {"team": "a"}}],
                "grants": [{"id": "team-a", "subject": {"kind": "any"}, "permission": "doc.read",
                  "target": {"kind": "doc"}, "effect": "allow",
                  "condition": {"op": "eq", "left": {"attr": "subject.team"}, "right": "a"}}]},
            "cases": [{"kind": "check", "subject": "user:bia", "permission": "doc.read",
                "resource": "doc:1", "expect": "allow", "grant": "team-a"}]}"#,
    );
    assert_eq!(result.outcome, Outcome::Passed, "{result:?}");
}

#[test]
fn an_unloaded_fixture_path_errors_the_file() {
    let report = run(&policy(), &[tests(r#"{"fixture": "f.json", "cases": []}"#)]);
    assert_eq!(report.results[0].outcome, Outcome::Errored);
}

#[test]
fn governance_cases_pass_and_fail_on_the_invariant() {
    let self_promotion = r#"{"kind": "mutation", "actor": "user:ana",
        "mutation": {"assign_role": {"subject": {"kind": "user", "id": "ana"}, "role": {"role": "reader"}}}"#;
    let refused = single(&format!(
        r#"{{"cases": [{self_promotion}, "expect": "refused", "invariant": "no_self_management"}}]}}"#
    ));
    assert_eq!(refused.outcome, Outcome::Passed, "{refused:?}");
    let wrong = single(&format!(r#"{{"cases": [{self_promotion}, "expect": "accepted"}}]}}"#));
    assert_eq!(wrong.outcome, Outcome::Failed);
    assert!(
        wrong.actual.starts_with("refused: [no_self_management]"),
        "{}",
        wrong.actual
    );
    let other = single(&format!(
        r#"{{"cases": [{self_promotion}, "expect": "refused", "invariant": "no_lockout"}}]}}"#
    ));
    assert_eq!(other.outcome, Outcome::Failed);
}

#[test]
fn a_mistake_inside_an_inline_value_is_reported_at_that_field() {
    let fixture = TestFile::parse("t", r#"{"fixture": {"grants": [{"id": "g"}]}, "cases": []}"#).unwrap_err();
    assert!(fixture.to_string().contains("missing field"), "{fixture}");
}

#[test]
fn an_empty_run_is_not_a_success() {
    assert!(!run(&policy(), &[]).is_success());
}

#[test]
fn unknown_fields_and_bad_json_are_refused_at_load() {
    assert!(TestFile::parse("t", r#"{"cases": [], "extra": 1}"#).is_err());
    assert!(TestFile::parse("t", r#"{"cases": [{"kind": "check", "expect": "maybe"}]}"#).is_err());
    assert!(TestFile::parse("t", "not json").is_err());
    let too_big = " ".repeat(strig::dsl::testing::MAX_TEST_BYTES + 1);
    assert!(TestFile::parse("t", &too_big).is_err());
}

#[test]
fn a_policy_that_does_not_build_is_one_error() {
    let mut broken = policy();
    broken.overrides.push(
        strig::OverrideSpec::new(strig::OverrideRule::ResourceOwner { attr: "o".into() })
            .with_except(vec!["nope".into()]),
    );
    let report = run(&broken, &[tests(r#"{"cases": []}"#)]);
    assert_eq!(report.results[0].outcome, Outcome::Errored);
    assert_eq!(report.results[0].file, "(policy)");
}
