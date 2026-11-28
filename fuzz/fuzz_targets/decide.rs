#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use strig::{
    Attributes, Catalog, Context, Effect, Engine, Grant, PermissionDef, Request, Resource, Subject,
};

#[derive(Deserialize)]
struct Input {
    grants: Vec<Grant>,
    subject: Subject,
    permission: String,
    resource: Resource,
    #[serde(default)]
    env: Attributes,
    #[serde(default)]
    now: Option<u64>,
}

fn engine() -> Engine {
    let catalog = Catalog::builder()
        .target_kinds(["document", "project"])
        .broad_target("org")
        .permission(PermissionDef::new("project.view").targets(["project"]))
        .permission(PermissionDef::new("project.edit").targets(["project"]))
        .permission(
            PermissionDef::new("document.view")
                .targets(["project", "document"])
                .implied_by(["project.view"]),
        )
        .permission(PermissionDef::new("org.manage").targets(["org"]))
        .build()
        .expect("fixed catalog");
    Engine::builder(catalog).build().expect("fixed engine")
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = serde_json::from_slice::<Input>(data) else {
        return;
    };
    let engine = engine();
    let mut ctx = Context::new(&input.grants).with_env(&input.env);
    ctx.now = input.now;
    let request = Request::new(&input.subject, &input.permission, &input.resource);

    let decision = engine.decide(&ctx, &request);
    assert_eq!(engine.check(&ctx, &request), decision.is_allowed());
    assert_eq!(decision, engine.decide(&ctx, &request), "decision must be deterministic");
    let _ = engine.explain(&ctx, &request);
    let _ = engine.capabilities(&ctx, &input.subject, &input.resource);

    if decision.effect == Effect::Allow {
        let candidate = input.grants.iter().any(|grant| {
            grant.effect == Effect::Allow && decision.matched.iter().any(|id| *id == grant.id)
        });
        assert!(candidate, "allowed without an allow grant among the candidates");
    }
});
