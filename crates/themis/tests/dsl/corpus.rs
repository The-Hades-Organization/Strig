//! Every scenario written in each syntax describes the same policy, comments included.

use crate::{LANGUAGES, SCENARIOS, source};
use themis::dsl::{Language, convert, parse, print};

/// The canonical JSON without where each note was written: the origin is not part of the policy.
fn canonical(policy: &themis::dsl::Policy) -> serde_json::Value {
    let mut json: serde_json::Value = serde_json::from_str(&policy.to_json().unwrap()).unwrap();
    if let Some(notes) = json.get_mut("notes").and_then(|notes| notes.as_array_mut()) {
        for note in notes {
            if let Some(note) = note.as_object_mut() {
                note.remove("origin");
            }
        }
    }
    json
}

fn read(scenario: &str, language: Language) -> themis::dsl::Parsed {
    let text = source(scenario, language);
    parse(&format!("{scenario}.{language}"), &text)
        .unwrap_or_else(|errors| panic!("{scenario} in {language} must parse:\n{errors}"))
}

#[test]
fn a_scenario_in_each_syntax_is_the_same_policy() {
    for scenario in SCENARIOS {
        let blocks = read(scenario, Language::Blocks);
        let json = canonical(&blocks.policy);
        for language in LANGUAGES {
            let other = read(scenario, language);
            assert_eq!(other.language, language);
            assert!(blocks.policy.equivalent(&other.policy), "{scenario}: {language} differs from blocks");
            let theirs = canonical(&other.policy);
            for key in json.as_object().unwrap().keys() {
                assert_eq!(theirs.get(key), json.get(key), "{scenario}: {language} differs in {key}");
            }
            assert_eq!(theirs, json, "{scenario}: {language} json differs");
        }
    }
}

#[test]
fn a_scenario_keeps_its_comments_in_every_syntax() {
    for scenario in SCENARIOS {
        let blocks = read(scenario, Language::Blocks);
        for language in LANGUAGES {
            let other = read(scenario, language);
            assert_eq!(blocks.policy.notes.len(), other.policy.notes.len(), "{scenario} in {language}");
        }
    }
}

#[test]
fn printing_a_scenario_reads_back_the_same_in_its_own_syntax() {
    for scenario in SCENARIOS {
        for language in LANGUAGES {
            let policy = read(scenario, language).policy;
            let text = print(&policy, language).unwrap_or_else(|error| panic!("{scenario} in {language}: {error}"));
            let again = parse("again", &text).unwrap_or_else(|errors| panic!("{scenario} in {language}:\n{errors}\n{text}"));
            assert!(policy.equivalent(&again.policy), "{scenario} in {language} lost something");
            assert_eq!(print(&again.policy, language).unwrap(), text, "{scenario} in {language} is not stable");
        }
    }
}

#[test]
fn converting_between_every_pair_keeps_the_policy() {
    for scenario in SCENARIOS {
        for from in LANGUAGES {
            let original = read(scenario, from).policy;
            let text = source(scenario, from);
            for to in LANGUAGES {
                let converted = convert(&text, to).unwrap_or_else(|error| panic!("{scenario} {from} to {to}: {error}"));
                let again = parse("converted", &converted)
                    .unwrap_or_else(|errors| panic!("{scenario} {from} to {to}:\n{errors}\n{converted}"));
                assert_eq!(again.language, to);
                assert!(original.equivalent(&again.policy), "{scenario} {from} to {to} lost something");
            }
        }
    }
}
