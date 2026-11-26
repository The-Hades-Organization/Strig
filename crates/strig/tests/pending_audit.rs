//! Trilha de auditoria do fluxo de pedido pendente (feature `audit`).

mod support;

use std::sync::Arc;

use strig::audit::{AuditAction, AuditLevel, AuditOutcome, Auditor, FailMode, MemoryAuditLog, verify_chain};
use strig::{
    ApprovalError, ApprovalPolicy, Approvals, Attributes, CatalogConformance, Governance, Grant, MemoryPendingStore,
    Mutation, MutationKind, NoSelfManagement, PendingStore, RequirePermission, Review, Subject,
};
use support::*;

const T0: u64 = 1_000;

fn admin(id: &str) -> Subject {
    Subject::user(id).with_role_in("admin", org())
}

fn base_grants() -> Vec<Grant> {
    vec![
        role_grant("admin-manage", "admin", "org.manage", true, at_org()),
        role_grant("member-view", "member", "project.view", true, at_org()),
    ]
}

fn governance() -> Governance {
    Governance::new()
        .with(CatalogConformance)
        .with(RequirePermission::new("org.roles.edit", project()))
        .with(NoSelfManagement)
}

fn policy() -> ApprovalPolicy {
    ApprovalPolicy::new().require(MutationKind::Add, "org.manage", project())
}

fn add(id: &str) -> Mutation {
    Mutation::Add(role_grant(id, "member", "project.edit", true, at_org()))
}

struct Scene {
    engine: strig::Engine,
    grants: Vec<Grant>,
    meta: Attributes,
}

impl Scene {
    fn new() -> Self {
        Self {
            engine: engine(),
            grants: base_grants(),
            meta: Attributes::new(),
        }
    }

    fn review(&self, now: u64) -> Review<'_> {
        Review {
            engine: &self.engine,
            current: &self.grants,
            tuples: None,
            now,
            meta: &self.meta,
        }
    }
}

fn violations_of(error: ApprovalError) -> Vec<String> {
    match error {
        ApprovalError::Refused(violations) => violations.into_iter().map(|v| v.invariant).collect(),
        other => panic!("esperava recusa, veio {other:?}"),
    }
}

fn audited() -> (Governance, Arc<MemoryAuditLog>) {
    let log = Arc::new(MemoryAuditLog::new());
    let auditor = Auditor::new(AuditLevel::Forensic, log.clone());
    (governance().audited(Arc::new(auditor)), log)
}

#[test]
fn every_step_leaves_a_chained_record() {
    let scene = Scene::new();
    let (gov, log) = audited();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);
    let ana = admin("ana");

    flow.propose(&scene.review(T0), &ana, &add("m-edit"), "r1", Some(T0 + 50))
        .unwrap();
    let _ = flow.approve(&scene.review(T0 + 1), &ana, "r1").unwrap_err();
    flow.approve(&scene.review(T0 + 2), &admin("caio"), "r1").unwrap();
    flow.propose(&scene.review(T0 + 3), &ana, &add("m-2"), "r2", None)
        .unwrap();
    flow.reject(&scene.review(T0 + 4), &admin("caio"), "r2", "duplicado")
        .unwrap();
    flow.propose(&scene.review(T0 + 5), &ana, &add("m-3"), "r3", Some(T0 + 6))
        .unwrap();
    flow.expire_due(T0 + 6, &scene.meta).unwrap();

    let records = log.records();
    let steps: Vec<(AuditAction, AuditOutcome)> = records.iter().map(|r| (r.action, r.outcome)).collect();
    assert_eq!(
        steps,
        [
            (AuditAction::MutationPropose, AuditOutcome::Pending),
            (AuditAction::MutationApprove, AuditOutcome::Rejected),
            (AuditAction::MutationApprove, AuditOutcome::Applied),
            (AuditAction::GrantAdd, AuditOutcome::Applied),
            (AuditAction::MutationPropose, AuditOutcome::Pending),
            (AuditAction::MutationReject, AuditOutcome::Applied),
            (AuditAction::MutationPropose, AuditOutcome::Pending),
            (AuditAction::MutationExpire, AuditOutcome::Applied),
        ]
    );
    verify_chain(&records).expect("a cadeia fecha");

    let refused = records[1].pending.as_ref().unwrap();
    assert_eq!((refused.id.as_str(), refused.author.as_str()), ("r1", "ana"));
    assert_eq!(records[1].actor, "ana");
    assert_eq!(records[1].violations.len(), 1);
    assert_eq!(records[2].actor, "caio");
    assert_eq!(records[3].actor, "ana");
    assert_eq!(
        records[5].pending.as_ref().unwrap().reason.as_deref(),
        Some("duplicado")
    );
    assert_eq!(records[7].actor, "strig-expiry");
}

#[test]
fn a_refused_proposal_is_in_the_trail_and_nothing_is_stored() {
    let scene = Scene::new();
    let (gov, log) = audited();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);

    let member = Subject::user("bia").with_role_in("member", org());
    assert!(
        flow.propose(&scene.review(T0), &member, &add("m-edit"), "r1", None)
            .is_err()
    );
    let records = log.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, AuditAction::MutationPropose);
    assert_eq!(records[0].outcome, AuditOutcome::Rejected);
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn a_sink_that_fails_in_closed_mode_refuses_the_step() {
    let scene = Scene::new();
    let sink = |_: &strig::AuditRecord| Err(strig::AuditError::Sink("fora do ar".into()));
    let auditor = Auditor::new(AuditLevel::Standard, Arc::new(sink)).with_fail_mode(FailMode::Closed);
    let gov = governance().audited(Arc::new(auditor));
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);

    let error = flow
        .propose(&scene.review(T0), &admin("ana"), &add("m-edit"), "r1", None)
        .unwrap_err();
    assert_eq!(violations_of(error), ["audit"]);
    assert!(store.list().unwrap().is_empty());
}
