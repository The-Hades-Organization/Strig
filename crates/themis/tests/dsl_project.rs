//! A project: sources merged into one policy, and the clashes between them.

use themis::dsl::{Language, Project};

const KINDS: &str = "language blocks\n\ntarget_kinds = [org, doc]\n";

const READ: &str = "\
language blocks

permission doc.read {
  targets = [doc]
}

invariant no_self_management {
}
";

fn project(sources: &[(&str, &str)]) -> Project {
    let mut project = Project::new();
    for (name, text) in sources {
        project
            .add_source(name, text)
            .unwrap_or_else(|errors| panic!("{name} must parse:\n{errors}"));
    }
    project
}

#[test]
fn sources_in_separate_files_merge_into_one_policy() {
    let built = project(&[("kinds.themis", KINDS), ("read.themis", READ)])
        .build()
        .unwrap_or_else(|errors| panic!("{errors}"));
    assert_eq!(built.policy.catalog.target_kinds, ["org", "doc"]);
    assert_eq!(built.policy.catalog.permissions.len(), 1);
    assert_eq!(built.policy.invariants.len(), 1);
    let at = built.origins.get("permission:doc.read").unwrap();
    assert_eq!((&*at.file, at.line, at.column), ("read.themis", 3, 12));
}

#[test]
fn the_order_of_the_sources_does_not_change_the_policy() {
    let forward = project(&[("kinds.themis", KINDS), ("read.themis", READ)])
        .build()
        .unwrap();
    let backward = project(&[("read.themis", READ), ("kinds.themis", KINDS)])
        .build()
        .unwrap();
    assert!(forward.policy.equivalent(&backward.policy));
}

#[test]
fn add_source_reports_the_language_it_read() {
    let mut project = Project::new();
    assert_eq!(project.add_source("a.themis", KINDS).unwrap(), Language::Blocks);
    assert_eq!(project.len(), 1);
    assert!(!project.is_empty());
}

#[test]
fn a_source_with_syntax_errors_is_not_added() {
    let mut project = Project::new();
    let errors = project.add_source("bad.themis", "target_kinds = [x]\n").unwrap_err();
    assert_eq!(errors.first().unwrap().location.as_ref().unwrap().line, 1);
    assert!(project.is_empty());
}

#[test]
fn a_file_name_cannot_be_added_twice() {
    let mut project = Project::new();
    project.add_source("a.themis", KINDS).unwrap();
    let errors = project.add_source("a.themis", KINDS).unwrap_err();
    assert!(errors.first().unwrap().message.contains("already added"));
    assert_eq!(project.len(), 1);
}

#[test]
fn a_file_cannot_hold_a_second_language_declaration() {
    let mut project = Project::new();
    let text = "language blocks\n\ntarget_kinds = [x]\n\nlanguage rules\n";
    let errors = project.add_source("mixed.themis", text).unwrap_err();
    let at = errors.first().unwrap().location.as_ref().unwrap();
    assert_eq!((at.line, at.column), (5, 1));
}

#[test]
fn a_permission_declared_in_two_files_points_at_both() {
    let other = "language blocks\n\n// again\npermission doc.read {\n  targets = [doc]\n}\n";
    let errors = project(&[("kinds.themis", KINDS), ("read.themis", READ), ("again.themis", other)])
        .build()
        .unwrap_err();
    let first = errors.first().unwrap();
    let at = first.location.as_ref().unwrap();
    let related = first.related.as_ref().unwrap();
    assert_eq!((&*at.file, at.line, at.column), ("again.themis", 4, 12));
    assert_eq!((&*related.file, related.line, related.column), ("read.themis", 3, 12));
    assert!(first.to_string().contains("(also at read.themis:3:12)"));
}

#[test]
fn a_grant_id_used_in_two_files_points_at_both() {
    let grant = |role: &str| {
        format!(
            "language blocks\n\ngrant g1 {{\n  effect = allow\n  subject = role {role}\n  permission = doc.read\n  target = doc\n}}\n"
        )
    };
    let errors = project(&[
        ("kinds.themis", KINDS),
        ("read.themis", READ),
        ("one.themis", &grant("a")),
        ("two.themis", &grant("b")),
    ])
    .build()
    .unwrap_err();
    let first = errors.first().unwrap();
    assert_eq!(&*first.location.as_ref().unwrap().file, "two.themis");
    assert_eq!(&*first.related.as_ref().unwrap().file, "one.themis");
}

#[test]
fn two_strategies_clash_and_one_strategy_is_taken() {
    let a = "language blocks\n\nstrategy = deny_overrides\n";
    let b = "language blocks\n\nstrategy = permit_overrides\n";
    let errors = project(&[("a.themis", a), ("b.themis", b)]).build().unwrap_err();
    assert!(errors.first().unwrap().message.contains("strategy"));
    let built = project(&[("a.themis", a), ("kinds.themis", KINDS)]).build().unwrap();
    assert_eq!(built.policy.strategy, themis::StrategySpec::DenyOverrides);
}

#[test]
fn a_subject_with_two_values_for_an_attribute_clashes() {
    let subject =
        |dept: &str| format!("language blocks\n\nsubject user:ana {{\n  attrs {{\n    dept = \"{dept}\"\n  }}\n}}\n");
    let errors = project(&[("a.themis", &subject("it")), ("b.themis", &subject("hr"))])
        .build()
        .unwrap_err();
    assert!(errors.first().unwrap().message.contains("dept"));
    assert_eq!(&*errors.first().unwrap().related.as_ref().unwrap().file, "a.themis");
}

#[test]
fn the_same_invariant_in_two_files_clashes_with_both_positions() {
    let one = "language blocks\n\ninvariant no_self_management {\n}\n\ninvariant prerequisites {\n}\n";
    let two = "language blocks\n\ninvariant prerequisites {\n}\n";
    let errors = project(&[("one.themis", one), ("two.themis", two)]).build().unwrap_err();
    let first = errors.first().unwrap();
    let at = first.location.as_ref().unwrap();
    assert_eq!((&*at.file, at.line), ("two.themis", 3));
    let related = first.related.as_ref().unwrap();
    assert_eq!((&*related.file, related.line), ("one.themis", 6));
}

#[test]
fn different_invariants_of_two_files_are_numbered_per_kind() {
    let one = "language blocks\n\ninvariant no_self_management {\n}\n\ninvariant prerequisites {\n}\n";
    let two = "language blocks\n\ninvariant catalog_conformance {\n}\n";
    let built = project(&[("one.themis", one), ("two.themis", two)]).build().unwrap();
    assert_eq!(built.policy.invariants.len(), 3);
    let at = built.origins.exact("invariant:catalog_conformance:1").unwrap();
    assert_eq!((&*at.file, at.line), ("two.themis", 3));
}

#[test]
fn a_repeat_word_for_word_across_files_is_a_clash() {
    let role = "language blocks\n\nrole r {\n}\n";
    let errors = project(&[("a.themis", role), ("b.themis", role)]).build().unwrap_err();
    let first = errors.first().unwrap();
    assert_eq!(&*first.location.as_ref().unwrap().file, "b.themis");
    assert_eq!(&*first.related.as_ref().unwrap().file, "a.themis");

    let errors = project(&[("a.themis", KINDS), ("b.themis", KINDS)]).build().unwrap_err();
    assert!(errors.first().unwrap().message.contains("target_kinds"));
}

#[test]
fn the_same_role_for_one_subject_in_two_files_clashes() {
    let subject = "language blocks\n\nsubject user:ana {\n  assign admin {\n  }\n}\n";
    let errors = project(&[("a.themis", subject), ("b.themis", subject)])
        .build()
        .unwrap_err();
    assert!(errors.first().unwrap().message.contains("admin"));
}

#[test]
fn a_project_takes_a_bounded_number_of_sources() {
    let mut project = Project::new();
    for at in 0..themis::dsl::MAX_SOURCES {
        project.add_source(&format!("{at}.themis"), "language blocks\n").unwrap();
    }
    let errors = project.add_source("one-more.themis", "language blocks\n").unwrap_err();
    assert!(errors.first().unwrap().message.contains("at most"));
    assert_eq!(project.len(), themis::dsl::MAX_SOURCES);
}

#[test]
fn notes_of_every_file_are_joined_with_their_own_file() {
    let a = "// first\nlanguage blocks\n\n// kinds\ntarget_kinds = [x]\n";
    let b = "language blocks\n\n// second\nrole r {\n}\n";
    let built = project(&[("a.themis", a), ("b.themis", b)]).build().unwrap();
    let files: Vec<_> = built
        .policy
        .notes
        .iter()
        .map(|n| (n.text.as_str(), n.origin.file.as_str()))
        .collect();
    assert_eq!(
        files,
        [("first", "a.themis"), ("kinds", "a.themis"), ("second", "b.themis")]
    );
}

#[test]
fn an_error_of_the_whole_is_found_after_the_merge() {
    // The permission targets a kind that only exists once the second file is added.
    let permission = "language blocks\n\npermission doc.read {\n  targets = [doc]\n}\n";
    assert!(project(&[("p.themis", permission)]).build().is_err());
    assert!(
        project(&[("p.themis", permission), ("k.themis", KINDS)])
            .build()
            .is_ok()
    );
}
