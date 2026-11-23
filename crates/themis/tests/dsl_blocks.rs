//! The Blocks syntax end to end: text to policy to JSON and back to text, comments included.

use themis::dsl::{Language, Placement, Policy, parse, print};

const SOURCE: &str = "\
// Access policy of a small workspace.
language blocks

target_kinds = [org, project]
strategy = deny_overrides

// Reading is the base of everything else.
permission org.read {
  targets = [org, project]
}

permission project.write {
  label = \"Write a project\"
  targets = [project]
  depends_on = [org.read]  // never alone
}

role editor {
}

role admin {
  inherits = [editor]
}

subject user:ana {
  attrs {
    dept = \"it\"
  }
  assign admin {
    scope = org:acme
    valid_from = 2026-01-01
    valid_until = 2026-12-31T23:59:59Z
  }
}

grant g1 {
  effect = allow
  subject = role editor
  permission = project.write
  target = project
  when = subject.dept == \"it\"
}

invariant no_self_management {
}
";

fn parsed() -> Policy {
    parse("policy.themis", SOURCE)
        .unwrap_or_else(|errors| panic!("the source must parse:\n{errors}"))
        .policy
}

#[test]
fn text_prints_back_as_the_same_text() {
    let policy = parsed();
    assert_eq!(print(&policy, Language::Blocks).unwrap(), SOURCE);
}

#[test]
fn text_survives_the_trip_through_json() {
    let policy = parsed();
    let json = policy.to_json().unwrap();
    let back = Policy::from_json(&json).unwrap();
    assert!(policy.equivalent(&back));
    assert_eq!(print(&back, Language::Blocks).unwrap(), SOURCE);
}

#[test]
fn every_comment_becomes_a_note_with_its_anchor_and_origin() {
    let policy = parsed();
    let notes: Vec<_> = policy
        .notes
        .iter()
        .map(|n| (n.text.as_str(), n.anchor.element.as_str(), n.anchor.placement))
        .collect();
    assert_eq!(
        notes,
        vec![
            ("Access policy of a small workspace.", "language", Placement::Before),
            (
                "Reading is the base of everything else.",
                "permission:org.read",
                Placement::Before
            ),
            ("never alone", "permission:project.write", Placement::Inline),
        ]
    );
    let origin = &policy.notes[1].origin;
    assert_eq!(
        (origin.file.as_str(), origin.line, origin.column),
        ("policy.themis", 7, 1)
    );
    assert_eq!(origin.language, Language::Blocks);
    assert_eq!(origin.field, None);
    assert_eq!(policy.notes[2].origin.field.as_deref(), Some("depends_on"));
}

#[test]
fn equivalence_ignores_where_the_comments_were_read() {
    let policy = parsed();
    let mut moved = policy.clone();
    for note in &mut moved.notes {
        note.origin.line += 40;
        note.origin.file = "other.themis".to_string();
    }
    assert!(policy.equivalent(&moved));
}

#[test]
fn equivalence_sees_a_comment_moved_to_another_element() {
    let policy = parsed();
    let mut moved = policy.clone();
    moved.notes[1].anchor.element = "permission:project.write".to_string();
    assert!(!policy.equivalent(&moved));
}

#[test]
fn equivalence_ignores_the_order_of_roles() {
    let policy = parsed();
    let mut reordered = policy.clone();
    reordered.roles.reverse();
    assert!(policy.equivalent(&reordered));
}

#[test]
fn json_has_the_notes_field() {
    let json: serde_json::Value = serde_json::from_str(&parsed().to_json().unwrap()).unwrap();
    let notes = json["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 3);
    assert_eq!(notes[2]["anchor"]["placement"], "inline");
    assert_eq!(notes[0]["origin"]["language"], "blocks");
}

#[test]
fn printing_twice_gives_the_same_text() {
    let once = print(&parsed(), Language::Blocks).unwrap();
    let again = print(&parse("policy.themis", &once).unwrap().policy, Language::Blocks).unwrap();
    assert_eq!(once, again);
}

const FULL: &str = "\
language blocks

target_kinds = [org, doc]
broad_targets = [org]
max_depth = 4

permission doc.read {
  targets = [doc]
}

permission doc.edit {
  targets = [doc]
  implied_by = [doc.read]
}

role viewer {
}

subject user:bob {
  principals = [bob]
  assign viewer {
  }
}

relation doc#owner {
  rewrite = this
}

relation doc#viewer {
  rewrite = this | owner
}

tuples {
  doc:d1#owner@user:bob
  doc:d1#viewer@org:acme#member
}

override resource_owner {
  attr = \"owner\"
  except = [doc.edit]
}

override permission_holder {
  permission = doc.read
}

invariant require_permission {
  permission = doc.read
  resource = org:acme > doc
}

invariant no_lockout {
  permissions = [doc.read]
  members = [user:bob]
  resource = doc:d1
  reserve_role = viewer
  reserve_subjects = [user:bob]
}

invariant forbid {
  subject = anyone
  permissions = [doc.edit]
}
";

#[test]
fn every_construct_prints_back_as_the_same_text() {
    let policy = parse("full.themis", FULL)
        .unwrap_or_else(|errors| panic!("the source must parse:\n{errors}"))
        .policy;
    assert_eq!(print(&policy, Language::Blocks).unwrap(), FULL);
    let back = Policy::from_json(&policy.to_json().unwrap()).unwrap();
    assert!(policy.equivalent(&back));
    assert_eq!(print(&back, Language::Blocks).unwrap(), FULL);
}

fn first_error(text: &str) -> (u32, u32, String) {
    let errors = parse("bad.themis", text).expect_err("the source must be refused");
    let first = errors.first().expect("at least one error");
    let at = first.location.as_ref().expect("a position");
    assert_eq!(&*at.file, "bad.themis");
    (at.line, at.column, first.message.clone())
}

#[test]
fn a_source_without_the_declaration_is_refused_at_its_first_token() {
    let (line, column, message) = first_error("target_kinds = [org]\n");
    assert_eq!((line, column), (1, 1));
    assert!(message.contains("declaring its language"), "{message}");
}

#[test]
fn an_unknown_language_is_refused_at_the_name() {
    let (line, column, message) = first_error("language yaml\n");
    assert_eq!((line, column), (1, 10));
    assert!(message.contains("unknown language `yaml`"), "{message}");
}

#[test]
fn every_known_language_is_read_from_its_declaration() {
    for text in ["// head\nlanguage rules\n", "// head\nlanguage actors\n"] {
        assert!(parse("empty.themis", text).is_ok(), "{text}");
    }
}

#[test]
fn an_unknown_field_is_refused_with_a_suggestion() {
    let text = "language blocks\n\npermission a.b {\n  targts = [x]\n}\n";
    let errors = parse("bad.themis", text).unwrap_err();
    let unknown = errors
        .iter()
        .find(|e| e.message.contains("unknown field `targts`"))
        .expect("the unknown field is reported");
    let at = unknown.location.as_ref().unwrap();
    assert_eq!((at.line, at.column), (4, 3));
    assert!(unknown.hint.as_deref().unwrap().contains("targets"));
}

#[test]
fn a_repeated_field_is_refused_at_the_second_line() {
    let text = "language blocks\n\npermission a.b {\n  targets = [x]\n  targets = [y]\n}\n";
    let (line, column, message) = first_error(text);
    assert_eq!((line, column), (5, 3));
    assert!(message.contains("given twice"), "{message}");
}

#[test]
fn a_permission_declared_twice_points_at_both_declarations() {
    let text = "language blocks\n\ntarget_kinds = [x]\n\npermission a.b {\n  targets = [x]\n}\n\npermission a.b {\n  targets = [x]\n}\n";
    let errors = parse("bad.themis", text).unwrap_err();
    let first = errors.first().unwrap();
    let at = first.location.as_ref().unwrap();
    let other = first.related.as_ref().expect("the first declaration");
    assert_eq!((at.line, at.column), (9, 12));
    assert_eq!((other.line, other.column), (5, 12));
    assert!(first.to_string().starts_with("bad.themis:9:12:"));
}

#[test]
fn a_missing_required_field_is_reported_at_the_block_name() {
    let (line, column, message) = first_error("language blocks\n\npermission a.b {\n}\n");
    assert_eq!((line, column), (3, 12));
    assert!(message.contains("needs `targets`"), "{message}");
}

#[test]
fn a_block_left_open_is_refused() {
    let errors = parse("bad.themis", "language blocks\n\nrole r {\n").unwrap_err();
    assert!(!errors.is_empty());
}

#[test]
fn a_date_outside_utc_is_refused_at_the_date() {
    let text =
        "language blocks\n\nsubject user:a {\n  assign r {\n    valid_from = 2026-01-01T00:00:00+02:00\n  }\n}\n";
    let (line, column, _) = first_error(text);
    assert_eq!((line, column), (5, 18));
}

#[test]
fn an_impossible_date_is_refused_at_the_date() {
    let text = "language blocks\n\nsubject user:a {\n  assign r {\n    valid_from = 2026-02-30\n  }\n}\n";
    let (line, column, _) = first_error(text);
    assert_eq!((line, column), (5, 18));
}

#[test]
fn an_oversized_source_is_refused_before_it_is_read() {
    let text = format!("language blocks\n// {}\n", "x".repeat(themis::dsl::MAX_SOURCE_BYTES));
    let (line, column, message) = first_error(&text);
    assert_eq!((line, column), (1, 1));
    assert!(message.contains("larger than"), "{message}");
}

#[test]
fn a_policy_loaded_from_json_is_validated_without_positions() {
    let json = r#"{"catalog":{"targetKinds":["x"],"permissions":[{"key":"a.b","targets":["y"]}]}}"#;
    let policy = Policy::from_json(json).unwrap();
    let errors = policy.validate().unwrap_err();
    assert!(errors.first().unwrap().location.is_none());
}
