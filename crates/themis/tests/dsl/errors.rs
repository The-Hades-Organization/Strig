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
    assert_eq!(errors.into_iter().next().and_then(|d| d.location).map(|l| l.line), Some(1));
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
    assert!(first.hint.is_some_and(|hint| hint.contains("rules") && hint.contains("actors")));
}

#[test]
fn an_unknown_permission_in_a_grant_points_into_the_file() {
    let rules = "language rules\n\nkinds doc\npermission doc.read on doc\nrole viewer\ng1: allow role viewer to doc.write on doc\n";
    let actors = "language actors\n\ncatalog\n  kinds doc\n  doc.read on doc\n\nrole viewer\n  allow doc.write on doc as g1\n";
    for text in [rules, actors] {
        let errors = parse("bad.themis", text).expect_err("doc.write is not declared");
        let line = errors.into_iter().find_map(|d| d.location).map(|l| l.line);
        assert!(line.is_some_and(|line| line > 2), "{text}");
    }
}
