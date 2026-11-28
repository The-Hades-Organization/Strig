#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use strig::{Attributes, Condition, ConditionRegistry, EvalContext, Resource, Subject};

#[derive(Deserialize)]
struct Input {
    condition: Condition,
    #[serde(default)]
    subject: Option<Subject>,
    #[serde(default)]
    resource: Resource,
    #[serde(default)]
    env: Attributes,
    #[serde(default)]
    now: Option<u64>,
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = serde_json::from_slice::<Input>(data) else {
        return;
    };
    let subject = input.subject.unwrap_or_else(|| Subject::user("u"));
    let ctx = EvalContext::new(&subject, &input.resource, &input.env);
    let registry = ConditionRegistry::new();
    let first = input.condition.evaluate_at(&ctx, &registry, input.now);
    let second = input.condition.evaluate_at(&ctx, &registry, input.now);
    assert_eq!(first, second, "evaluation must be deterministic");
    let _ = input.condition.evaluate(&ctx, &registry);
    let _ = input.condition.uses_tz();
    let _ = input.condition.functions();
});
