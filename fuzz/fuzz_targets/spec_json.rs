#![no_main]

use libfuzzer_sys::fuzz_target;
use strig::EngineSpec;

fuzz_target!(|data: &[u8]| {
    let Ok(spec) = serde_json::from_slice::<EngineSpec>(data) else {
        return;
    };
    let _ = spec.build();
    let json = serde_json::to_string(&spec).expect("a spec always serializes");
    let back: EngineSpec = serde_json::from_str(&json).expect("a serialized spec must be readable");
    assert_eq!(back, spec);
});
