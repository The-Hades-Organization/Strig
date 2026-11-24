//! Auditoria da posse exclusiva: aquisição, preempção, recusa, liberação e expiração.
#![cfg(all(feature = "exclusive", feature = "audit"))]

use std::sync::Arc;

use strig::{
    Anchor, AuditAction, AuditLevel, AuditOutcome, Auditor, Catalog, Claim, Context, Engine, ExclusiveRegistry, Grant,
    MemoryAuditLog, ObjectRef, PermissionDef, Preemption, Resource, Subject, SubjectMatcher, TargetSelector, Terms,
};

fn user(id: &str) -> ObjectRef {
    ObjectRef::new("user", id)
}

fn doc() -> ObjectRef {
    ObjectRef::new("document", "d1")
}

fn registry(level: AuditLevel) -> (ExclusiveRegistry, Arc<MemoryAuditLog>) {
    let log = Arc::new(MemoryAuditLog::new());
    let registry = ExclusiveRegistry::default().with_audit(Arc::new(Auditor::new(level, log.clone())));
    (registry, log)
}

#[test]
fn every_change_of_ownership_is_recorded_with_the_caller_time() {
    let (mut registry, log) = registry(AuditLevel::Standard);
    let claim = |holder: &str, priority| Claim::new(doc(), user(holder), Terms::new(priority, 100));

    registry.acquire(&claim("alice", 1), 10, Preemption::Forbidden).unwrap();
    registry.acquire(&claim("bob", 9), 20, Preemption::Allowed).unwrap();
    registry.acquire(&claim("carol", 1), 30, Preemption::Allowed).unwrap();
    registry.release(&doc(), &user("bob"), 40).unwrap();
    registry.acquire(&claim("alice", 1), 50, Preemption::Forbidden).unwrap();
    registry.expire(500).unwrap();

    let trail: Vec<_> = log
        .records()
        .into_iter()
        .map(|r| (r.at, r.action, r.outcome, r.actor, r.object))
        .collect();
    let object = || doc().to_string();
    assert_eq!(
        trail,
        vec![
            (
                10,
                AuditAction::ExclusiveAcquire,
                AuditOutcome::Applied,
                "alice".into(),
                object()
            ),
            (
                20,
                AuditAction::ExclusivePreempt,
                AuditOutcome::Applied,
                "bob".into(),
                object()
            ),
            (
                30,
                AuditAction::ExclusiveAcquire,
                AuditOutcome::Rejected,
                "carol".into(),
                object()
            ),
            (
                40,
                AuditAction::ExclusiveRelease,
                AuditOutcome::Applied,
                "bob".into(),
                object()
            ),
            (
                50,
                AuditAction::ExclusiveAcquire,
                AuditOutcome::Applied,
                "alice".into(),
                object()
            ),
            (
                500,
                AuditAction::ExclusiveExpire,
                AuditOutcome::Applied,
                "alice".into(),
                object()
            ),
        ]
    );
}

#[test]
fn detailed_level_keeps_priority_and_the_other_holder() {
    let (mut registry, log) = registry(AuditLevel::Detailed);
    let claim = |holder: &str, priority| Claim::new(doc(), user(holder), Terms::new(priority, 100));
    registry.acquire(&claim("alice", 1), 0, Preemption::Forbidden).unwrap();
    registry.acquire(&claim("bob", 9), 5, Preemption::Allowed).unwrap();

    let preempt = &log.records()[1];

    assert_eq!(preempt.action, AuditAction::ExclusivePreempt);
    assert_eq!(preempt.meta.get("priority"), Some(&strig::Value::Int(9)));
    assert_eq!(
        preempt.meta.get("other_holder"),
        Some(&strig::Value::Str("user:alice".into()))
    );
}

#[test]
fn permission_refusal_is_recorded_as_rejected() {
    let catalog = Catalog::builder()
        .target_kinds(["document"])
        .broad_target("org")
        .permission(PermissionDef::new("exclusive.hold").targets(["org", "document"]))
        .permission(PermissionDef::new("exclusive.preempt").targets(["org", "document"]))
        .build()
        .unwrap();
    let engine = Engine::builder(catalog).build().unwrap();
    let grants: Vec<Grant> = vec![
        Grant::allow(
            "g1",
            SubjectMatcher::role("editor"),
            "exclusive.hold",
            TargetSelector::exact("org", "o1"),
        )
        .scoped(Anchor::new("org", "o1")),
    ];
    let ctx = Context::new(&grants);
    let (mut registry, log) = registry(AuditLevel::Standard);
    let resource = Resource::new("document", "d1").within("org", "o1");
    let editor = |id: &str| Subject::user(id).with_role_in("editor", Anchor::new("org", "o1"));
    registry
        .acquire_checked(&engine, &ctx, &editor("alice"), &resource, Terms::new(1, 100), 0)
        .unwrap();

    let refused = registry.acquire_checked(&engine, &ctx, &editor("bob"), &resource, Terms::new(9, 100), 5);

    assert!(refused.is_err());
    let last = log.records().pop().unwrap();
    assert_eq!(
        (last.action, last.outcome, last.actor.as_str()),
        (AuditAction::ExclusiveAcquire, AuditOutcome::Rejected, "bob")
    );
}
