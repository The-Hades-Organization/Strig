use super::*;
use crate::dsl::Project;
use crate::query::QueryLimits;

fn build(text: &str) -> crate::dsl::Built {
    let mut project = Project::new();
    project.add_source("p.strig", text).unwrap();
    project.build().unwrap()
}

fn codes(text: &str) -> Vec<String> {
    let built = build(text);
    lint(&built.policy, Some(&built.origins), &LintOptions::default())
        .into_iter()
        .map(|f| format!("{} {}", f.code, f.element))
        .collect()
}

const HEAD: &str = "language blocks\n\ntarget_kinds = [doc]\n\n";

fn perm(key: &str) -> String {
    format!("permission {key} {{\n  targets = [doc]\n}}\n\n")
}

fn grant(id: &str, effect: &str, subject: &str, permission: &str, extra: &str) -> String {
    format!(
        "grant {id} {{\n  effect = {effect}\n  subject = {subject}\n  permission = {permission}\n  target = doc\n{extra}}}\n\n"
    )
}

#[test]
fn a_clean_policy_has_no_findings() {
    let text = format!(
        "{HEAD}{}role r {{\n}}\n\n{}",
        perm("doc.read"),
        grant("g", "allow", "role r", "doc.read", "")
    );
    assert_eq!(codes(&text), Vec::<String>::new());
}

#[test]
fn a_deny_shadows_an_allow_at_the_same_step() {
    let text = format!(
        "{HEAD}{}{}{}",
        perm("doc.read"),
        grant("g-deny", "deny", "anyone", "doc.read", ""),
        grant("g-allow", "allow", "user ana", "doc.read", ""),
    );
    assert_eq!(codes(&text), ["L001 grant:g-allow"]);
}

#[test]
fn a_more_specific_allow_is_not_shadowed_by_a_broader_deny() {
    let text = format!(
        "{HEAD}{}{}{}",
        perm("doc.read"),
        grant("g-deny", "deny", "anyone", "doc.read", "").replace("target = doc", "target = global"),
        grant("g-allow", "allow", "anyone", "doc.read", ""),
    );
    let found = codes(&text);
    assert!(!found.iter().any(|c| c.starts_with("L001")), "{found:?}");
}

#[test]
fn a_role_inheriting_the_covering_role_is_shadowed() {
    let text = format!(
        "{HEAD}{}role base {{\n}}\n\nrole top {{\n  inherits = [base]\n}}\n\n{}{}",
        perm("doc.read"),
        grant("g-deny", "deny", "role base", "doc.read", ""),
        grant("g-allow", "allow", "role top", "doc.read", ""),
    );
    assert_eq!(codes(&text), ["L001 grant:g-allow"]);
}

#[test]
fn a_condition_keeps_a_broader_grant_from_shadowing() {
    let text = format!(
        "{HEAD}{}{}{}",
        perm("doc.read"),
        grant("g-deny", "deny", "anyone", "doc.read", "  when = subject.level == 1\n"),
        grant("g-allow", "allow", "user ana", "doc.read", ""),
    );
    assert_eq!(codes(&text), Vec::<String>::new());
}

#[test]
fn first_applicable_shadows_the_later_grant() {
    let text = format!(
        "{HEAD}strategy = first_applicable\n\n{}{}{}",
        perm("doc.read"),
        grant("g1", "allow", "anyone", "doc.read", ""),
        grant("g2", "allow", "user ana", "doc.read", ""),
    );
    assert_eq!(codes(&text), ["L001 grant:g2"]);
}

#[test]
fn a_deny_with_nothing_to_take_away_is_unreachable() {
    let text = format!(
        "{HEAD}{}{}",
        perm("doc.read"),
        grant("g-deny", "deny", "anyone", "doc.read", "")
    );
    let found = codes(&text);
    assert!(found.contains(&"L002 grant:g-deny".to_string()), "{found:?}");
}

#[test]
fn a_deny_over_a_permission_someone_holds_is_reachable() {
    let text = format!(
        "{HEAD}{}{}{}",
        perm("doc.read"),
        grant("g-allow", "allow", "role r", "doc.read", ""),
        grant("g-deny", "deny", "user ana", "doc.read", "")
    )
    .replace("grant g-allow", "role r {\n}\n\ngrant g-allow");
    assert!(!codes(&text).iter().any(|c| c.starts_with("L002")));
}

#[test]
fn a_permission_nobody_holds_is_reported() {
    let text = format!(
        "{HEAD}{}{}role r {{\n}}\n\n{}",
        perm("doc.read"),
        perm("doc.edit"),
        grant("g", "allow", "role r", "doc.read", "")
    );
    assert_eq!(codes(&text), ["L003 permission:doc.edit"]);
}

#[test]
fn a_permission_held_through_a_more_general_one_is_not_reported() {
    let text = format!(
        "{HEAD}permission doc.read {{\n  targets = [doc]\n  implied_by = [doc.manage]\n}}\n\n{}role r {{\n}}\n\n{}",
        perm("doc.manage"),
        grant("g", "allow", "role r", "doc.manage", "")
    );
    assert_eq!(codes(&text), Vec::<String>::new());
}

#[test]
fn an_isolated_role_is_unused_and_a_linked_one_is_not() {
    let text = format!(
        "{HEAD}{}role used {{\n}}\n\nrole child {{\n  inherits = [used]\n}}\n\nrole lonely {{\n}}\n\n{}",
        perm("doc.read"),
        grant("g", "allow", "role used", "doc.read", "")
    );
    assert_eq!(codes(&text), ["L004 role:lonely"]);
}

#[test]
fn a_role_assigned_to_a_subject_is_used() {
    let text = format!(
        "{HEAD}{}role r {{\n}}\n\nsubject user:ana {{\n  assign r {{\n  }}\n}}\n\n{}",
        perm("doc.read"),
        grant("g", "allow", "user ana", "doc.read", "")
    );
    assert_eq!(codes(&text), Vec::<String>::new());
}

#[test]
fn an_implied_by_already_implied_by_another_entry_is_redundant() {
    let text = format!(
        "{HEAD}{}permission doc.edit {{\n  targets = [doc]\n  implied_by = [doc.manage]\n}}\n\n\
         permission doc.read {{\n  targets = [doc]\n  implied_by = [doc.edit, doc.manage]\n}}\n\nrole r {{\n}}\n\n{}",
        perm("doc.manage"),
        grant("g", "allow", "role r", "doc.manage", "")
    );
    let built = build(&text);
    let found = lint(&built.policy, Some(&built.origins), &LintOptions::default());
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].code, "L005");
    assert!(found[0].message.contains("`doc.manage` in `implied_by` of `doc.read`"), "{found:?}");
}

#[test]
fn a_condition_false_or_true_for_any_input_is_reported() {
    let always_false = grant("g-false", "allow", "anyone", "doc.read", "  when = 1 == 2\n");
    let contradiction = grant(
        "g-contradiction",
        "allow",
        "anyone",
        "doc.read",
        "  when = subject.a == 1 and not subject.a == 1\n",
    );
    let always_true = grant("g-true", "allow", "anyone", "doc.read", "  when = 1 == 1\n");
    let text = format!("{HEAD}{}{always_false}{contradiction}{always_true}", perm("doc.read"));
    let found = codes(&text);
    assert!(found.contains(&"L006 grant:g-false".to_string()), "{found:?}");
    assert!(found.contains(&"L006 grant:g-contradiction".to_string()), "{found:?}");
    assert!(found.contains(&"L007 grant:g-true".to_string()), "{found:?}");
}

#[test]
fn a_condition_that_reads_data_is_left_alone() {
    let text = format!(
        "{HEAD}{}{}",
        perm("doc.read"),
        grant("g", "allow", "anyone", "doc.read", "  when = subject.level >= 2\n")
    );
    assert_eq!(codes(&text), Vec::<String>::new());
}

#[test]
fn a_declared_field_no_allow_reaches_is_reported() {
    let text = format!(
        "{HEAD}permission doc.edit {{\n  targets = [doc]\n  fields = [title, body]\n}}\n\nrole r {{\n}}\n\n{}",
        grant("g", "allow", "role r", "doc.edit", "  fields = [title]\n")
    );
    let built = build(&text);
    let found = lint(&built.policy, Some(&built.origins), &LintOptions::default());
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].code, "L008");
    assert!(found[0].message.contains("field `body`"), "{found:?}");
}

#[test]
fn findings_carry_position_severity_and_hint_and_can_be_ignored() {
    let text = format!(
        "{HEAD}{}{}",
        perm("doc.read"),
        grant("g-deny", "deny", "anyone", "doc.read", "")
    );
    let built = build(&text);
    let all = lint(&built.policy, Some(&built.origins), &LintOptions::default());
    let finding = all.iter().find(|f| f.code == "L002").unwrap();
    assert_eq!(finding.severity, Severity::Warning);
    assert!(finding.position().is_some_and(|p| p.starts_with("p.strig:")), "{finding:?}");
    assert!(!finding.hint.is_empty());
    let options = LintOptions::default().ignoring("unreachable-deny").ignoring("l003");
    assert!(lint(&built.policy, Some(&built.origins), &options).is_empty());
}

#[test]
fn every_code_has_a_distinct_code_and_name() {
    let mut seen = std::collections::BTreeSet::new();
    for code in LintCode::ALL {
        assert!(seen.insert(code.code()) && seen.insert(code.name()));
        assert_eq!(LintCode::parse(code.code()), Some(code));
        assert_eq!(LintCode::parse(code.name()), Some(code));
    }
    assert_eq!(LintCode::parse("L999"), None);
}

const BASE: &str = "language blocks\n\ntarget_kinds = [doc]\n\npermission doc.read {\n  targets = [doc]\n}\n\n\
role reader {\n}\n\nrole editor {\n}\n\n";

fn diff_of(before: &str, after: &str, fixture: &DiffFixture) -> PolicyDiff {
    let (b, a) = (build(before), build(after));
    diff(
        DiffSide::new(&b.policy).with_origins(&b.origins),
        DiffSide::new(&a.policy).with_origins(&a.origins),
        fixture,
        &DiffOptions::default(),
    )
    .unwrap()
}

fn allow_reader() -> String {
    format!("{BASE}{}", grant("g", "allow", "role reader", "doc.read", ""))
}

#[test]
fn the_same_policy_has_no_change() {
    let policy = allow_reader();
    let found = diff_of(&policy, &policy, &DiffFixture::default());
    assert!(found.is_empty(), "{found:?}");
    assert!(found.universe.questions > 0 && !found.universe.partial && found.universe.derived);
}

#[test]
fn a_new_allow_widens_access_and_names_the_responsible_grant() {
    let before = allow_reader();
    let after = format!("{before}{}", grant("g2", "allow", "role editor", "doc.read", ""));
    let found = diff_of(&before, &after, &DiffFixture::default());
    assert_eq!(found.count(ChangeKind::Narrowed), 0);
    let change = found
        .changes
        .iter()
        .find(|c| c.subject == "role:editor" && c.resource == "doc:(any)")
        .unwrap_or_else(|| panic!("{found:?}"));
    assert_eq!(change.change, ChangeKind::Widened);
    assert_eq!(change.permission, "doc.read");
    assert_eq!(change.before.reason, "no_applicable_grant");
    assert_eq!(change.after.grant.as_deref(), Some("g2"));
    assert!(change.after.at.as_deref().is_some_and(|a| a.starts_with("p.strig:")), "{change:?}");
}

#[test]
fn a_new_deny_narrows_access() {
    let before = allow_reader();
    let after = format!("{before}{}", grant("g-no", "deny", "role reader", "doc.read", ""));
    let found = diff_of(&before, &after, &DiffFixture::default());
    assert!(found.count(ChangeKind::Narrowed) >= 1, "{found:?}");
    assert_eq!(found.count(ChangeKind::Widened), 0);
    let change = &found.changes[0];
    assert_eq!(change.before.grant.as_deref(), Some("g"));
    assert_eq!(change.after.grant.as_deref(), Some("g-no"));
}

#[test]
fn moving_the_deciding_grant_without_changing_the_answer_is_no_change() {
    let before = allow_reader();
    let after = before.replace("grant g {", "grant renamed {");
    assert!(diff_of(&before, &after, &DiffFixture::default()).is_empty());
}

#[test]
fn a_role_taken_from_a_declared_subject_shows_up() {
    let with_role = format!(
        "{}subject user:ana {{\n  assign reader {{\n  }}\n}}\n\n",
        allow_reader()
    );
    let without = format!("{}subject user:ana {{\n}}\n\n", allow_reader());
    let found = diff_of(&with_role, &without, &DiffFixture::default());
    let change = found.changes.iter().find(|c| c.subject == "user:ana").unwrap();
    assert_eq!(change.change, ChangeKind::Narrowed);
}

#[test]
fn an_explicit_fixture_bounds_the_questions() {
    let before = allow_reader();
    let after = format!("{before}{}", grant("g2", "allow", "anyone", "doc.read", ""));
    let fixture = DiffFixture::parse(
        "f.json",
        r#"{"subjects": [{"kind": "user", "id": "bia"}], "resources": ["doc:1"], "permissions": ["doc.read"]}"#,
    )
    .unwrap();
    let found = diff_of(&before, &after, &fixture);
    assert!(!found.universe.derived);
    assert_eq!(found.universe.questions, 1);
    assert_eq!(found.changes.len(), 1);
    assert_eq!(found.changes[0].subject, "user:bia");
    assert_eq!(found.changes[0].resource, "doc:1");
}

#[test]
fn a_fixture_grant_applies_to_both_sides() {
    let before = allow_reader();
    let after = format!("{before}{}", grant("g2", "deny", "anyone", "doc.read", ""));
    let fixture = DiffFixture::parse(
        "f.json",
        r#"{"subjects": [{"kind": "user", "id": "bia"}], "resources": ["doc:1"],
            "grants": [{"id": "fx", "subject": {"kind": "user", "id": "bia"}, "permission": "doc.read",
                        "target": {"kind": "doc"}, "effect": "allow"}]}"#,
    )
    .unwrap();
    let found = diff_of(&before, &after, &fixture);
    assert_eq!(found.changes.len(), 1, "{found:?}");
    assert_eq!(found.changes[0].change, ChangeKind::Narrowed);
    assert_eq!(found.changes[0].before.grant.as_deref(), Some("fx"));
}

#[test]
fn a_fixture_grant_repeating_a_policy_id_is_an_error() {
    let policy = build(&allow_reader());
    let fixture = DiffFixture::parse(
        "f.json",
        r#"{"grants": [{"id": "g", "subject": {"kind": "any"}, "permission": "doc.read",
                        "target": {"kind": "doc"}, "effect": "allow"}]}"#,
    )
    .unwrap();
    let side = DiffSide::new(&policy.policy);
    let error = diff(side, side, &fixture, &DiffOptions::default()).unwrap_err();
    assert!(error.to_string().contains("repeats an id"), "{error}");
}

#[test]
fn a_limit_marks_the_result_partial() {
    let before = allow_reader();
    let after = format!("{before}{}", grant("g2", "allow", "anyone", "doc.read", ""));
    let (b, a) = (build(&before), build(&after));
    let options = DiffOptions::default().with_limits(QueryLimits::default().with_max_decisions(4));
    let found = diff(
        DiffSide::new(&b.policy),
        DiffSide::new(&a.policy),
        &DiffFixture::default(),
        &options,
    )
    .unwrap();
    assert!(found.universe.partial);
    assert_eq!(found.universe.questions, 2);
}

#[test]
fn a_removed_permission_narrows_with_unknown_permission() {
    let before = allow_reader();
    let after = "language blocks\n\ntarget_kinds = [doc]\n".to_string();
    let found = diff_of(&before, &after, &DiffFixture::default());
    assert!(found.count(ChangeKind::Narrowed) >= 1, "{found:?}");
    assert!(found.changes.iter().all(|c| c.after.reason == "unknown_permission"), "{found:?}");
}
