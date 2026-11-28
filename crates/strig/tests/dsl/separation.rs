//! Separation of duties in the three syntaxes: the same policy, the schema it exports, the way it
//! reads back, and the errors a wrong declaration gets.

use strig::dsl::{Language, Policy, parse, print};
use strig::{ExclusiveKind, InvariantSpec};

const BLOCKS: &str = "language blocks

target_kinds = [org, payment]

permission payment.create {
  targets = [payment]
}

permission payment.approve {
  targets = [payment]
}

mutually_exclusive payment_duties {
  of = roles
  members = [maker, checker]
  anchor = org
}

mutually_exclusive create_or_approve {
  of = permissions
  members = [payment.create, payment.approve]
}

conflicting_actions four_eyes {
  first = [payment.create]
  then = [payment.approve]
  history = trail
  distinct_roles = true
}

role maker {}

role checker {}

invariant separation_of_duties {
  subjects = [user:ana]
}
";

const RULES: &str = "language rules

kinds org, payment

permission payment.create on payment
permission payment.approve on payment

mutually-exclusive payment_duties of roles members [maker, checker] anchor org
mutually-exclusive create_or_approve of permissions members [payment.create, payment.approve]
conflicting-actions four_eyes first [payment.create] then [payment.approve] history trail distinct_roles true

role maker
role checker

always separation-of-duties subjects [user:ana]
";

const ACTORS: &str = "language actors

catalog
  kinds org, payment
  payment.create on payment
  payment.approve on payment
  mutually-exclusive payment_duties of roles members [maker, checker] anchor org
  mutually-exclusive create_or_approve of permissions members [payment.create, payment.approve]
  conflicting-actions four_eyes first [payment.create] then [payment.approve] history trail distinct_roles true

role maker
role checker

governance
  separation-of-duties subjects [user:ana]
";

fn source(language: Language) -> &'static str {
    match language {
        Language::Blocks => BLOCKS,
        Language::Rules => RULES,
        Language::Actors => ACTORS,
        _ => unreachable!("a new syntax needs its own source"),
    }
}

const LANGUAGES: [Language; 3] = [Language::Blocks, Language::Rules, Language::Actors];

fn policy(language: Language) -> Policy {
    parse("p.strig", source(language))
        .unwrap_or_else(|errors| panic!("{language}:\n{errors}"))
        .policy
}

#[test]
fn the_three_syntaxes_declare_the_same_policy() {
    let expected = policy(Language::Blocks).to_json().unwrap();
    for language in LANGUAGES {
        assert_eq!(policy(language).to_json().unwrap(), expected, "{language}");
    }
}

#[test]
fn the_declarations_are_read_whole() {
    let catalog = policy(Language::Rules).catalog;
    let [duties, by_permission] = catalog.mutually_exclusive.as_slice() else {
        panic!("{:?}", catalog.mutually_exclusive);
    };
    assert_eq!(duties.name, "payment_duties");
    assert_eq!(duties.of, ExclusiveKind::Roles);
    assert_eq!(duties.members, ["maker", "checker"]);
    assert_eq!(duties.anchor.as_deref(), Some("org"));
    assert_eq!(by_permission.of, ExclusiveKind::Permissions);
    assert_eq!(by_permission.anchor, None);
    let [rule] = catalog.conflicting_actions.as_slice() else {
        panic!("{:?}", catalog.conflicting_actions);
    };
    assert_eq!(rule.history, "trail");
    assert!(rule.distinct_roles);
    assert!(matches!(
        policy(Language::Rules).invariants.as_slice(),
        [InvariantSpec::SeparationOfDuties { subjects }] if subjects.len() == 1
    ));
}

#[test]
fn a_policy_with_separation_exports_schema_5() {
    for language in LANGUAGES {
        let json = policy(language).to_json().unwrap();
        assert!(json.starts_with("{\n  \"schema\": 5,\n"), "{language}");
        assert!(Policy::from_json(&json).is_ok(), "{language}");
    }
}

#[test]
fn an_older_reader_refuses_the_schema() {
    let json = policy(Language::Blocks).to_json().unwrap();
    let newer = json.replacen("\"schema\": 5", "\"schema\": 6", 1);
    assert!(Policy::from_json(&newer).is_err());
}

#[test]
fn a_policy_prints_and_reads_back_in_every_syntax() {
    let expected = policy(Language::Blocks).to_json().unwrap();
    for from in LANGUAGES {
        for to in LANGUAGES {
            let text = print(&policy(from), to).unwrap_or_else(|e| panic!("{from} to {to}: {e}"));
            let back = parse("p.strig", &text)
                .unwrap_or_else(|errors| panic!("{from} to {to}:\n{errors}\n{text}"))
                .policy;
            assert_eq!(back.to_json().unwrap(), expected, "{from} to {to}:\n{text}");
        }
    }
}

fn errors_of(language: Language, edit: impl Fn(&str) -> String) -> String {
    match parse("p.strig", &edit(source(language))) {
        Ok(parsed) => match parsed.policy.validate() {
            Ok(_) => panic!("{language}: the policy was accepted"),
            Err(errors) => errors.to_string(),
        },
        Err(errors) => errors.to_string(),
    }
}

#[test]
fn a_member_that_is_not_a_permission_is_refused_with_the_set_named() {
    let text = errors_of(Language::Rules, |s| {
        s.replace(
            "members [payment.create, payment.approve]",
            "members [payment.create, payment.nope]",
        )
    });
    assert!(text.contains("create_or_approve"), "{text}");
    assert!(text.contains("payment.nope"), "{text}");
}

#[test]
fn a_set_of_one_is_refused() {
    let text = errors_of(Language::Rules, |s| {
        s.replace("members [maker, checker]", "members [maker]")
    });
    assert!(text.contains("payment_duties"), "{text}");
}

#[test]
fn an_unknown_anchor_is_refused() {
    let text = errors_of(Language::Blocks, |s| s.replace("anchor = org", "anchor = galaxy"));
    assert!(text.contains("galaxy"), "{text}");
}

#[test]
fn a_set_of_neither_roles_nor_permissions_is_refused_with_a_hint() {
    for language in LANGUAGES {
        let text = errors_of(language, |s| {
            s.replace("of roles", "of users").replace("of = roles", "of = users")
        });
        assert!(text.contains("users"), "{language}: {text}");
    }
}

#[test]
fn a_name_given_twice_is_refused() {
    let text = errors_of(Language::Rules, |s| {
        s.replace(
            "conflicting-actions four_eyes",
            "mutually-exclusive payment_duties of roles members [maker, checker]\nconflicting-actions four_eyes",
        )
    });
    assert!(text.contains("payment_duties"), "{text}");
}

#[test]
fn an_unknown_field_gets_a_suggestion() {
    let text = errors_of(Language::Rules, |s| {
        s.replace("distinct_roles true", "distinct_role true")
    });
    assert!(text.contains("distinct_roles"), "{text}");
}

#[test]
fn a_project_keeps_the_separation_declared_in_each_file_and_refuses_a_name_declared_twice() {
    let mut project = strig::dsl::Project::new();
    project.add_source("a.strig", BLOCKS).unwrap();
    let other = "language blocks\n\nmutually_exclusive extra {\n  of = roles\n  members = [maker, auditor]\n}\n\nrole auditor {}\n";
    project.add_source("b.strig", other).unwrap();
    let built = project.build().unwrap_or_else(|errors| panic!("{errors}"));
    let names: Vec<_> = built
        .policy
        .catalog
        .mutually_exclusive
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(names, ["payment_duties", "create_or_approve", "extra"]);
    assert_eq!(built.policy.catalog.conflicting_actions.len(), 1);

    let mut twice = strig::dsl::Project::new();
    twice.add_source("a.strig", BLOCKS).unwrap();
    let again = "language blocks\n\nmutually_exclusive payment_duties {\n  of = roles\n  members = [maker, auditor]\n}\n\nrole auditor {}\n";
    twice.add_source("b.strig", again).unwrap();
    let errors = twice.build().err().expect("a name declared twice").to_string();
    assert!(errors.contains("payment_duties"), "{errors}");
}

#[test]
fn a_role_that_inherits_two_members_of_a_role_set_is_refused_at_the_role() {
    let text = errors_of(Language::Blocks, |s| {
        s.replace(
            "role maker {}\n",
            "role maker {}\n\nrole both {\n  inherits = [maker, checker]\n}\n",
        )
    });
    assert!(text.contains("role `both`"), "{text}");
    assert!(text.contains("payment_duties"), "{text}");
}

#[test]
fn a_role_that_inherits_one_member_is_accepted() {
    let policy = parse(
        "p.strig",
        &BLOCKS.replace(
            "role maker {}\n",
            "role maker {}\n\nrole lead {\n  inherits = [checker]\n}\n",
        ),
    )
    .unwrap()
    .policy;
    assert!(policy.validate().is_ok());
}
