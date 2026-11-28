#![no_main]

use libfuzzer_sys::fuzz_target;
use strig::dsl::{format, is_formatted};

fuzz_target!(|text: &str| {
    let Ok(once) = format("fuzz.strig", text) else {
        return;
    };
    let twice = format("fuzz.strig", &once).expect("formatted output must parse again");
    assert_eq!(once, twice, "format must be idempotent");
    assert!(is_formatted("fuzz.strig", &once).unwrap());
});
