//! The policy language and its JSON are frozen: the canonical JSON of every scenario is committed under
//! `tests/dsl/frozen/`, and the text -> JSON -> text round trip is pinned for every supported schema.
//! A diff here is a breaking change (see `docs/versioning.md`). Regenerate on purpose with
//! `STRIG_UPDATE_FROZEN=1 cargo test -p strig --features dsl-fs --test dsl frozen`.

use std::path::PathBuf;

use strig::dsl::{DSL_SCHEMA, Language, Policy, parse, print};

use crate::{LANGUAGES, SCENARIOS, canonical, source};

fn file(scenario: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/dsl/frozen")
        .join(format!("{scenario}.json"))
}

fn exported(scenario: &str, language: Language) -> String {
    let text = source(scenario, language);
    let mut json = parse(scenario, &text)
        .unwrap_or_else(|errors| panic!("{scenario} in {language}:\n{errors}"))
        .policy
        .to_json()
        .unwrap();
    json.push('\n');
    json
}

fn schema_of(json: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(json).unwrap()["schema"]
        .as_u64()
        .unwrap_or(1)
}

#[test]
fn the_json_of_every_scenario_is_the_committed_one() {
    for scenario in SCENARIOS {
        let written = exported(scenario, Language::Blocks);
        let path = file(scenario);
        if std::env::var_os("STRIG_UPDATE_FROZEN").is_some() {
            std::fs::write(&path, &written).unwrap();
        }
        let frozen = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}; run with STRIG_UPDATE_FROZEN=1 to create it", path.display()));
        assert_eq!(
            written, frozen,
            "{scenario}: the policy JSON changed, which is a breaking change; update on purpose with STRIG_UPDATE_FROZEN=1"
        );
    }
}

#[test]
fn the_json_of_a_scenario_is_the_same_in_every_syntax() {
    for scenario in SCENARIOS {
        let policy = |language| {
            let mut json: serde_json::Value = serde_json::from_str(&exported(scenario, language)).unwrap();
            for note in json
                .get_mut("notes")
                .and_then(|n| n.as_array_mut())
                .into_iter()
                .flatten()
            {
                note.as_object_mut().unwrap().remove("origin");
            }
            json
        };
        let blocks = policy(Language::Blocks);
        for language in LANGUAGES {
            assert_eq!(policy(language), blocks, "{scenario} in {language}");
        }
    }
}

#[test]
fn text_to_json_to_text_is_stable_in_every_syntax() {
    for scenario in SCENARIOS {
        let frozen = std::fs::read_to_string(file(scenario)).unwrap();
        let policy = Policy::from_json(&frozen).unwrap_or_else(|e| panic!("{scenario}: {e}"));
        for language in LANGUAGES {
            let text = print(&policy, language).unwrap();
            let again = parse(scenario, &text).unwrap_or_else(|errors| panic!("{scenario} in {language}:\n{errors}"));
            assert!(policy.equivalent(&again.policy), "{scenario} in {language}");
            assert_eq!(
                print(&again.policy, language).unwrap(),
                text,
                "{scenario} in {language}"
            );
            assert_eq!(
                canonical(&again.policy),
                canonical(&policy),
                "{scenario} in {language}: json -> text -> json changed"
            );
        }
    }
}

#[test]
fn every_supported_schema_has_a_committed_policy_and_none_is_newer() {
    let mut seen = std::collections::BTreeSet::new();
    for scenario in SCENARIOS {
        let schema = schema_of(&std::fs::read_to_string(file(scenario)).unwrap());
        assert!(schema <= u64::from(DSL_SCHEMA), "{scenario} is schema {schema}");
        seen.insert(schema);
    }
    for schema in 1..=u64::from(DSL_SCHEMA) {
        if schema == 2 {
            continue; // a policy of schema 2 is written without the number, like schema 1
        }
        assert!(seen.contains(&schema), "no committed policy exports schema {schema}");
    }
}
