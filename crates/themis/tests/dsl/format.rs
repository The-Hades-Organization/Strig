//! The formatter: canonical output, idempotence over the corpus, comments kept, errors positioned.

use crate::{LANGUAGES, SCENARIOS, canonical, source};
use themis::dsl::{FormatError, format, is_formatted, parse};

const MESSY: &str = "language blocks



target_kinds = [org]   // kinds


permission org.read {
      targets = [org]   // targets
}
";

const TIDY: &str = "language blocks

target_kinds = [org]  // kinds

permission org.read {
  targets = [org]  // targets
}
";

#[test]
fn formatting_the_corpus_twice_gives_the_same_text() {
    for scenario in SCENARIOS {
        for language in LANGUAGES {
            let once = format("c", &source(scenario, language)).unwrap_or_else(|e| panic!("{scenario} {language}: {e}"));
            assert_eq!(
                format("c", &once).unwrap(),
                once,
                "{scenario} in {language} is not idempotent"
            );
            assert!(is_formatted("c", &once).unwrap(), "{scenario} in {language}");
        }
    }
}

#[test]
fn formatting_the_corpus_keeps_the_policy_and_its_comments() {
    for scenario in SCENARIOS {
        for language in LANGUAGES {
            let text = source(scenario, language);
            let before = parse("a", &text).unwrap();
            let after = parse("b", &format("c", &text).unwrap()).unwrap();
            assert_eq!(after.language, language);
            assert_eq!(canonical(&before.policy), canonical(&after.policy), "{scenario} {language}");
        }
    }
}

#[test]
fn a_badly_spaced_source_becomes_the_canonical_text() {
    assert_eq!(format("m", MESSY).unwrap(), TIDY);
}

#[test]
fn a_comment_survives_formatting() {
    let out = format("m", MESSY).unwrap();
    assert!(out.contains("// kinds") && out.contains("// targets"), "{out}");
}

#[test]
fn is_formatted_tells_without_rewriting() {
    assert!(!is_formatted("m", MESSY).unwrap());
    assert!(is_formatted("m", TIDY).unwrap());
}

#[test]
fn a_source_that_does_not_compile_is_an_error_with_a_position() {
    let Err(FormatError::Parse(found)) = format("broken.themis", "language blocks\n\npermission {\n") else {
        panic!("must fail to parse");
    };
    let at = found.first().unwrap().location.as_ref().unwrap();
    assert_eq!(&*at.file, "broken.themis");
    assert!(at.line >= 1 && at.column >= 1);
    assert!(is_formatted("x", "nothing").is_err());
}

#[test]
fn an_empty_source_is_an_error_not_a_blank_file() {
    assert!(matches!(format("e", ""), Err(FormatError::Parse(_))));
}
