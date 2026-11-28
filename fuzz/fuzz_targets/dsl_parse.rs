#![no_main]

use libfuzzer_sys::fuzz_target;
use strig::dsl::{Policy, parse};

fuzz_target!(|text: &str| {
    let Ok(parsed) = parse("fuzz.strig", text) else {
        return;
    };
    assert!(parsed.policy.validate().is_ok(), "a parsed policy must validate");
    let json = parsed.policy.to_json().expect("a policy always serializes");
    let back = Policy::from_json(&json).expect("the canonical JSON must be readable");
    assert!(back.validate().is_ok(), "the canonical JSON must validate");
});
