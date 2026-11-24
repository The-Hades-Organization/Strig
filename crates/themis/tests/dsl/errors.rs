//! Errors point at a line and column in every syntax.

use crate::LANGUAGES;
use themis::dsl::{Language, parse};

fn first_error(language: Language, body: &str) -> (u32, u32) {
    let text = format!("language {language}\n\n{body}");
    let errors = parse("bad.themis", &text).expect_err("the source is wrong");
    let at = errors
        .into_iter()
        .next()
        .and_then(|d| d.location)
        .expect("an error with a position");
    (at.line, at.column)
}

#[test]
fn an_unknown_word_is_reported_on_its_line_in_every_syntax() {
    for language in LANGUAGES {
        let (line, _) = first_error(language, "frobnicate everything\n");
        assert_eq!(line, 3, "{language}");
    }
}

#[test]
fn a_missing_language_line_is_reported_in_every_syntax() {
    let errors = parse("bad.themis", "role viewer\n").expect_err("no language");
    assert_eq!(
        errors.into_iter().next().and_then(|d| d.location).map(|l| l.line),
        Some(1)
    );
}

#[test]
fn a_second_language_line_is_an_error_in_every_syntax() {
    for language in LANGUAGES {
        let text = format!("language {language}\n\nlanguage {language}\n");
        let errors = parse("mixed.themis", &text).expect_err("two language lines");
        let line = errors.into_iter().next().and_then(|d| d.location).map(|l| l.line);
        assert_eq!(line, Some(3), "{language}");
    }
}

#[test]
fn a_file_cannot_switch_syntax_half_way() {
    for (first, second) in [
        (Language::Blocks, Language::Rules),
        (Language::Rules, Language::Actors),
        (Language::Actors, Language::Blocks),
    ] {
        let text = format!("language {first}\n\nlanguage {second}\n");
        assert!(parse("mixed.themis", &text).is_err(), "{first} then {second}");
    }
}

#[test]
fn an_unknown_language_is_reported_with_the_choices() {
    let errors = parse("bad.themis", "language prose\n").expect_err("unknown language");
    let first = errors.into_iter().next().unwrap();
    assert!(
        first
            .hint
            .is_some_and(|hint| hint.contains("rules") && hint.contains("actors"))
    );
}

#[test]
fn an_unknown_permission_in_a_grant_points_into_the_file() {
    let rules = "language rules\n\nkinds doc\npermission doc.read on doc\nrole viewer\ng1: allow role viewer to doc.write on doc\n";
    let actors =
        "language actors\n\ncatalog\n  kinds doc\n  doc.read on doc\n\nrole viewer\n  allow doc.write on doc as g1\n";
    for text in [rules, actors] {
        let errors = parse("bad.themis", text).expect_err("doc.write is not declared");
        let line = errors.into_iter().find_map(|d| d.location).map(|l| l.line);
        assert!(line.is_some_and(|line| line > 2), "{text}");
    }
}

/// The matching scenario with one piece of a condition swapped for a bad one.
fn matching_with(language: Language, good: &str, bad: &str) -> String {
    let text = crate::source("matching", language);
    assert!(text.contains(good), "{language} has no `{good}`");
    text.replacen(good, bad, 1)
}

#[test]
fn a_bad_cidr_time_or_day_is_pointed_at_with_a_hint_in_every_syntax() {
    let cases = [
        (
            r#""10.0.0.0/8", "2001:db8::/32""#,
            r#""10.0.0.0/33", "2001:db8::/32""#,
            "CIDR",
        ),
        (r#"ip_in "192.168.0.0/16""#, r#"ip_in "192.168.0.0/16/8""#, "CIDR"),
        (
            r#"time_between "09:00" "17:30""#,
            r#"time_between "9:00" "17:30""#,
            "time of day",
        ),
        (
            r#"time_between "22:00" "06:00""#,
            r#"time_between "22:00" "24:00""#,
            "time of day",
        ),
        (r#""thu", "fri""#, r#""thu", "friday""#, "day of the week"),
    ];
    for language in LANGUAGES {
        for (good, bad, what) in cases {
            let text = matching_with(language, good, bad);
            let errors = parse("bad.themis", &text).expect_err("the condition is wrong");
            let first = errors.into_iter().next().unwrap();
            assert!(first.message.contains(what), "{language} {bad}: {}", first.message);
            assert!(first.hint.is_some(), "{language} {bad}: no hint");
            let wrong_line = text.lines().position(|l| l.contains(bad)).unwrap() as u32 + 1;
            assert_eq!(first.location.map(|l| l.line), Some(wrong_line), "{language} {bad}");
        }
    }
}

#[test]
fn a_bad_cidr_time_or_day_in_the_json_fails_validation_with_a_hint() {
    let policy = parse("p", &crate::source("matching", Language::Blocks)).unwrap().policy;
    let json = policy.to_json().unwrap();
    for (good, bad, what) in [
        (r#""10.0.0.0/8""#, r#""10.0.0.0/33""#, "CIDR"),
        (r#""09:00""#, r#""25:00""#, "time of day"),
        (r#""wed""#, r#""wednesday""#, "day of the week"),
    ] {
        assert!(json.contains(good));
        let broken = themis::dsl::Policy::from_json(&json.replacen(good, bad, 1)).unwrap();
        let errors = broken.validate().expect_err("the policy is wrong");
        let first = errors.into_iter().next().unwrap();
        assert!(first.message.contains(what), "{bad}: {}", first.message);
        assert!(first.hint.is_some(), "{bad}");
    }
}
