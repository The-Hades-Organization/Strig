//! A name the validator does not know comes with the nearest known one, when there is one.

use crate::LANGUAGES;
use strig::dsl::{Language, parse};

/// The hint of the first problem whose message holds `message`.
fn hint_of(text: &str, message: &str) -> Option<String> {
    let errors = parse("bad.strig", text).expect_err("the source is wrong");
    let found = errors
        .into_iter()
        .find(|d| d.message.contains(message))
        .unwrap_or_else(|| panic!("no problem says `{message}` in:\n{text}"));
    found.hint
}

fn catalog(language: Language) -> &'static str {
    match language {
        Language::Blocks => {
            "target_kinds = [doc]\n\npermission doc.read {\n  targets = [doc]\n}\n\npermission doc.edit {\n  targets = [doc]\n}\n\n"
        }
        Language::Rules => "kinds doc\npermission doc.read on doc\npermission doc.edit on doc\n",
        _ => "catalog\n  kinds doc\n  doc.read on doc\n  doc.edit on doc\n",
    }
}

/// A source with the two permissions and the role `editor`, plus `extra`.
fn source(language: Language, extra: &str) -> String {
    let role = match language {
        Language::Blocks => "role editor {\n}\n\n",
        _ => "role editor\n\n",
    };
    match language {
        Language::Actors => format!("language {language}\n\n{role}{extra}\n{}", catalog(language)),
        _ => format!("language {language}\n\n{}{role}{extra}", catalog(language)),
    }
}

fn grant(language: Language, permission: &str) -> String {
    match language {
        Language::Blocks => format!(
            "grant g1 {{\n  effect = allow\n  subject = role editor\n  permission = {permission}\n  target = doc\n}}\n"
        ),
        Language::Rules => format!("g1: allow role editor to {permission} on doc\n"),
        _ => format!("role editor\n  allow {permission} on doc as g1\n"),
    }
}

#[test]
fn an_unknown_permission_in_a_grant_names_the_close_one_in_every_syntax() {
    for language in LANGUAGES {
        let text = source(language, &grant(language, "doc.edti"));
        let hint = hint_of(&text, "unknown permission `doc.edti`").expect("a hint");
        assert!(hint.starts_with("did you mean `doc.edit`?"), "{language}: {hint}");
    }
}

#[test]
fn an_unknown_permission_far_from_every_name_gets_no_did_you_mean() {
    for language in LANGUAGES {
        let text = source(language, &grant(language, "invoice.archive"));
        let hint = hint_of(&text, "unknown permission `invoice.archive`").unwrap_or_default();
        assert!(!hint.contains("did you mean"), "{language}: {hint}");
    }
}

#[test]
fn a_tie_in_distance_is_settled_alphabetically() {
    // `doc.reae` is one edit from `doc.read` and from `doc.reap`.
    let text = source(
        Language::Rules,
        "permission doc.reap on doc\ng1: allow role editor to doc.reae on doc\n",
    );
    let hint = hint_of(&text, "unknown permission `doc.reae`").expect("a hint");
    assert!(hint.starts_with("did you mean `doc.read`?"), "{hint}");
}

#[test]
fn an_unknown_parent_role_names_the_close_one_in_every_syntax() {
    for language in LANGUAGES {
        let text = match language {
            Language::Blocks => "role editor {\n}\n\nrole manager {\n  inherits = [edtor]\n}\n",
            Language::Rules => "role editor\nrole manager inherits edtor\n",
            _ => "role editor\n\nrole manager inherits edtor\n",
        };
        let text = format!("language {language}\n\n{text}");
        let hint = hint_of(&text, "inherits `edtor`").expect("a hint");
        assert!(hint.starts_with("did you mean `editor`?"), "{language}: {hint}");
        assert!(hint.contains("declare it with"), "{language}: {hint}");
    }
}

#[test]
fn an_unknown_assigned_role_names_the_close_one_in_every_syntax() {
    for language in LANGUAGES {
        let assignment = match language {
            Language::Blocks => "subject user:ana {\n  assign edtor {\n  }\n}\n",
            Language::Rules => "user:ana has role edtor\n",
            _ => "subject user:ana\n  role edtor\n",
        };
        let text = source(language, assignment);
        let hint = hint_of(&text, "role `edtor` is not declared").expect("a hint");
        assert!(hint.starts_with("did you mean `editor`?"), "{language}: {hint}");
    }
}

#[test]
fn an_unknown_role_far_from_every_declared_one_gets_no_did_you_mean() {
    let text = source(Language::Rules, "user:ana has role zzzzzzzz\n");
    let hint = hint_of(&text, "role `zzzzzzzz` is not declared").unwrap_or_default();
    assert!(!hint.contains("did you mean"), "{hint}");
}

#[test]
fn an_unknown_permission_in_an_invariant_names_the_close_one() {
    let text = source(Language::Rules, "always forbid subject anyone permissions [doc.edti]\n");
    let hint = hint_of(&text, "unknown permission `doc.edti`").expect("a hint");
    assert_eq!(hint, "did you mean `doc.edit`?");
}

#[test]
fn an_unknown_prerequisite_names_the_close_permission() {
    let text = format!(
        "language rules\n\n{}permission doc.share on doc depends_on doc.raed\n",
        catalog(Language::Rules)
    );
    let hint = hint_of(&text, "depends on `doc.raed`").expect("a hint");
    assert!(hint.starts_with("did you mean `doc.read`?"), "{hint}");
}

#[test]
fn an_unknown_target_kind_names_the_close_one() {
    let text = "language rules\n\nkinds doc\npermission doc.read on dcc\n";
    let hint = hint_of(text, "`dcc`").expect("a hint");
    assert!(hint.starts_with("did you mean `doc`?"), "{hint}");
}
