#![no_main]

use libfuzzer_sys::fuzz_target;
use strig::dsl::{Language, convert, parse};

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
            again.policy.to_json().unwrap(),
            original.policy.to_json().unwrap(),
            "convert to {to} changed the policy"
        );
        let back = convert(&converted, original.language).expect("the way back must work");
        let round = parse("round.strig", &back).expect("round trip must parse");
        assert_eq!(
            round.policy.to_json().unwrap(),
            original.policy.to_json().unwrap(),
            "round trip through {to} changed the policy"
        );
    }
});
