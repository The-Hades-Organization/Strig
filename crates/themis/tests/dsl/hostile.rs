//! Rules and Actors on hostile input: bounded work, no panic, an error with a position.

use themis::dsl::{Language, MAX_SOURCE_BYTES, parse};

const NEW: [Language; 2] = [Language::Rules, Language::Actors];

fn header(language: Language) -> String {
    format!("language {language}\n")
}

#[test]
fn a_single_huge_line_is_read_or_refused() {
    for language in NEW {
        let text = format!("{}role {}\n", header(language), "a".repeat(1_000_000));
        let _ = parse("long.themis", &text);
    }
}

#[test]
fn a_source_over_the_limit_is_refused_with_a_position() {
    for language in NEW {
        let text = format!(
            "{}{}",
            header(language),
            "# padding\n".repeat(MAX_SOURCE_BYTES / 10 + 1)
        );
        let errors = parse("big.themis", &text).expect_err("over the limit");
        assert!(errors.into_iter().next().unwrap().location.is_some(), "{language}");
    }
}

#[test]
fn a_hundred_thousand_roles_with_a_ring_end_with_a_capped_report() {
    let total = 100_000;
    for language in NEW {
        let mut text = header(language);
        for at in 0..total {
            let next = (at + 1) % total;
            text.push_str(&format!("role r{at} inherits r{next}\n"));
        }
        let errors = parse("ring.themis", &text).expect_err("a cycle");
        assert!(errors.len() <= 101, "{language}: {} errors", errors.len());
    }
}

#[test]
fn a_condition_nested_past_the_limit_is_an_error() {
    let depth = 5_000;
    let condition = format!("{}subject.a == 1{}", "(".repeat(depth), ")".repeat(depth));
    let rules = format!(
        "language rules\n\nkinds doc\npermission doc.read on doc\nrole r\ng: allow role r to doc.read on doc when {condition}\n"
    );
    let actors = format!(
        "language actors\n\ncatalog\n  kinds doc\n  doc.read on doc\n\nrole r\n  allow doc.read on doc as g when {condition}\n"
    );
    for text in [rules, actors] {
        assert!(parse("deep.themis", &text).is_err());
    }
}

#[test]
fn deep_indentation_in_actors_is_an_error() {
    let mut text = header(Language::Actors);
    for level in 0..2_000 {
        text.push_str(&" ".repeat(level * 2));
        text.push_str("role r\n");
    }
    assert!(parse("indent.themis", &text).is_err());
}

#[test]
fn stray_bytes_never_panic() {
    let noise = [
        "\u{0}", "\t\t", "\r\n", "\u{feff}", "é", "\"", "'", "(((", ")))", "[", "]", "#", "->", "==",
    ];
    for language in NEW {
        for chunk in noise {
            let text = format!(
                "{}{}\n  {}\nrole {}\n",
                header(language),
                chunk.repeat(50),
                chunk,
                chunk
            );
            let _ = parse("noise.themis", &text);
        }
    }
}

#[test]
fn a_source_of_nothing_but_garbage_has_a_capped_report() {
    for language in NEW {
        let text = format!("{}{}", header(language), "@@@ ??? $$$\n".repeat(50_000));
        let errors = parse("garbage.themis", &text).expect_err("garbage");
        assert!(errors.len() <= 101, "{language}: {}", errors.len());
    }
}

#[test]
fn a_hundred_thousand_empty_lines_and_comments_are_read() {
    for language in NEW {
        let text = format!("{}{}", header(language), "\n# note\n".repeat(100_000));
        let _ = parse("blank.themis", &text);
    }
}
