#![no_main]

use libfuzzer_sys::fuzz_target;
use strig::dsl::{Language, Policy, convert, parse};

/// The canonical JSON without where each comment was read: that is the one thing a conversion changes.
fn canonical(policy: &Policy) -> serde_json::Value {
    let mut json: serde_json::Value = serde_json::from_str(&policy.to_json().unwrap()).unwrap();
    if let Some(notes) = json.get_mut("notes").and_then(|n| n.as_array_mut()) {
        for note in notes {
            if let Some(fields) = note.as_object_mut() {
                fields.remove("origin");
            }
        }
    }
    json
}

const LANGUAGES: [Language; 3] = [Language::Blocks, Language::Rules, Language::Actors];

fuzz_target!(|text: &str| {
    let Ok(original) = parse("fuzz.strig", text) else {
        return;
    };
    for to in LANGUAGES {
        let Ok(converted) = convert(text, to) else {
            continue;
        };
        let again = parse("converted.strig", &converted).expect("converted output must parse");
        assert_eq!(again.language, to);
        assert_eq!(
            canonical(&again.policy),
            canonical(&original.policy),
            "convert to {to} changed the policy"
        );
        let back = convert(&converted, original.language).expect("the way back must work");
        let round = parse("round.strig", &back).expect("round trip must parse");
        assert_eq!(
            canonical(&round.policy),
            canonical(&original.policy),
            "round trip through {to} changed the policy"
        );
    }
});
