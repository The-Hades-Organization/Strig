//! Elevação temporária e break-glass (feature `audit`).

mod support;

use std::sync::Arc;

use strig::audit::{AuditAction, AuditLevel, Auditor, FailMode, MemoryAuditLog, verify_chain};
use strig::{
    ApprovalError, Attributes, CatalogConformance, Elevated, ElevationPolicy, ElevationRequest, ElevationRule,
    ElevationTarget, Elevations, Governance, Grant, MemoryPendingStore, PendingStatus, PendingStore, Review,
    ReviewState, Subject, TargetSelector,
};
use support::*;

const T0: u64 = 10_000;
const HOUR: u64 = 3_600_000;

fn admin(id: &str) -> Subject {
    Subject::user(id).with_role_in("admin", org())
}

fn ana() -> Subject {
    Subject::user("ana").with_role_in("member", org())
}

fn base_grants() -> Vec<Grant> {
    vec![role_grant("admin-manage", "admin", "org.manage", true, at_org())]
}

fn edit() -> ElevationTarget {
    ElevationTarget::permission("project.edit", TargetSelector::exact("project", PROJECT)).scoped(org())
}

fn rule() -> ElevationRule {
    ElevationRule::new(edit().key(), 4 * HOUR, "org.manage", project()).requiring_justification()
}

fn policy() -> ElevationPolicy {
    ElevationPolicy::new().with(rule())
}

fn break_glass_policy() -> ElevationPolicy {
    ElevationPolicy::new().with(rule().allowing_break_glass(HOUR))
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

fn governance() -> Governance {
    Governance::new().with(CatalogConformance)
}

fn audited(level: AuditLevel) -> (Governance, Arc<MemoryAuditLog>) {
    let log = Arc::new(MemoryAuditLog::new());
    let auditor = Auditor::new(level, log.clone());
    (governance().audited(Arc::new(auditor)), log)
}

fn ask(id: &str, duration: u64) -> ElevationRequest {
    ElevationRequest::new(id, ana(), edit(), duration).justified("incidente 42")
}

fn pending(elevated: Elevated) -> strig::PendingRequest {
    match elevated {
        Elevated::Pending(request) => request,
        other => panic!("esperava pedido pendente, veio {other:?}"),
    }
}

#[test]
fn an_approved_elevation_opens_a_window_from_the_approval() {
    let scene = Scene::new();
    let gov = governance();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    pending(flow.request(&scene.review(T0), &ask("e1", 2 * HOUR), None).unwrap());
    assert!(flow.active(T0).unwrap().is_empty());

    let approved = flow.approve(&scene.review(T0 + 500), &admin("bia"), "e1").unwrap();
    let grant = approved
        .grants
        .iter()
        .find(|g| g.id == "elevation:e1")
        .expect("grant da elevação");
    assert_eq!(grant.valid_from, Some(T0 + 500));
    assert_eq!(grant.valid_until, Some(T0 + 500 + 2 * HOUR));
    assert!(matches!(approved.request.status, PendingStatus::Approved { .. }));

    assert_eq!(flow.active(T0 + 500).unwrap().len(), 1);
    assert_eq!(flow.active(T0 + 500 + 2 * HOUR - 1).unwrap().len(), 1);
    assert!(flow.active(T0 + 500 + 2 * HOUR).unwrap().is_empty());
}

#[test]
fn a_role_elevation_becomes_a_role_assignment_with_a_window() {
    let scene = Scene::new();
    let gov = governance();
    let target = ElevationTarget::role("admin").scoped(org());
    let policy = ElevationPolicy::new().with(ElevationRule::new(target.key(), HOUR, "org.manage", project()));
    let store = MemoryPendingStore::new();
    let flow = Elevations::new(&gov, &policy, &store);

    pending(
        flow.request(
            &scene.review(T0),
            &ElevationRequest::new("r1", ana(), target, HOUR),
            None,
        )
        .unwrap(),
    );
    let approved = flow.approve(&scene.review(T0 + 10), &admin("bia"), "r1").unwrap();
    assert_eq!(approved.grants, base_grants());
    match approved.request.mutation {
        strig::Mutation::AssignRole { ref role, .. } => {
            assert_eq!(role.valid_from, Some(T0 + 10));
            assert_eq!(role.valid_until, Some(T0 + 10 + HOUR));
        }
        ref other => panic!("esperava AssignRole, veio {other:?}"),
    }
}

#[test]
fn a_duration_over_the_maximum_is_refused() {
    let scene = Scene::new();
    let gov = governance();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    let error = flow
        .request(&scene.review(T0), &ask("e1", 4 * HOUR + 1), None)
        .unwrap_err();
    assert_eq!(violations_of(error), ["elevation_duration"]);
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn a_request_without_justification_is_refused() {
    let scene = Scene::new();
    let gov = governance();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    let request = ElevationRequest::new("e1", ana(), edit(), HOUR);
    let error = flow.request(&scene.review(T0), &request, None).unwrap_err();
    assert_eq!(violations_of(error), ["elevation_justification"]);
}

#[test]
fn a_target_the_policy_does_not_list_is_refused() {
    let scene = Scene::new();
    let gov = governance();
    let (policy, store) = (ElevationPolicy::new(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    let error = flow.request(&scene.review(T0), &ask("e1", HOUR), None).unwrap_err();
    assert_eq!(violations_of(error), ["elevation_policy"]);
}

#[test]
fn the_author_never_approves_their_own_request() {
    let scene = Scene::new();
    let gov = governance();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);
    let author = admin("ana");

    let request = ElevationRequest::new("e1", author.clone(), edit(), HOUR).justified("preciso");
    pending(flow.request(&scene.review(T0), &request, None).unwrap());
    let error = flow.approve(&scene.review(T0 + 1), &author, "e1").unwrap_err();
    assert!(matches!(error, ApprovalError::Refused(_)), "veio {error:?}");
    assert!(store.get("e1").unwrap().unwrap().is_pending());
}

#[test]
fn an_approver_without_the_permission_is_refused() {
    let scene = Scene::new();
    let gov = governance();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    pending(flow.request(&scene.review(T0), &ask("e1", HOUR), None).unwrap());
    let error = flow
        .approve(
            &scene.review(T0 + 1),
            &Subject::user("caio").with_role_in("member", org()),
            "e1",
        )
        .unwrap_err();
    assert!(matches!(error, ApprovalError::Refused(_)), "veio {error:?}");
}

#[test]
fn a_policy_tightened_after_the_request_refuses_the_approval() {
    let scene = Scene::new();
    let gov = governance();
    let store = MemoryPendingStore::new();
    let loose = policy();
    pending(
        Elevations::new(&gov, &loose, &store)
            .request(&scene.review(T0), &ask("e1", 3 * HOUR), None)
            .unwrap(),
    );
    let tight = ElevationPolicy::new().with(ElevationRule::new(edit().key(), HOUR, "org.manage", project()));
    let error = Elevations::new(&gov, &tight, &store)
        .approve(&scene.review(T0 + 1), &admin("bia"), "e1")
        .unwrap_err();
    assert_eq!(violations_of(error), ["elevation_duration"]);
}

#[test]
fn rejecting_closes_the_request_without_a_grant() {
    let scene = Scene::new();
    let gov = governance();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    pending(flow.request(&scene.review(T0), &ask("e1", HOUR), None).unwrap());
    let closed = flow
        .reject(&scene.review(T0 + 1), &admin("bia"), "e1", "sem motivo")
        .unwrap();
    assert!(matches!(closed.status, PendingStatus::Rejected { .. }));
    assert!(flow.active(T0 + 2).unwrap().is_empty());
}

#[test]
fn the_actor_revokes_their_own_elevation_early() {
    let mut scene = Scene::new();
    let gov = governance();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    pending(flow.request(&scene.review(T0), &ask("e1", 2 * HOUR), None).unwrap());
    scene.grants = flow.approve(&scene.review(T0 + 1), &admin("bia"), "e1").unwrap().grants;

    let revoked = flow
        .revoke(&scene.review(T0 + 100), &ana(), "e1", Some("terminei"))
        .unwrap();
    assert_eq!(revoked.request.elevation.unwrap().revoked.unwrap().at, T0 + 100);
    assert!(flow.active(T0 + 101).unwrap().is_empty());

    let again = flow.revoke(&scene.review(T0 + 200), &ana(), "e1", None).unwrap_err();
    assert_eq!(violations_of(again), ["elevation_state"]);
}

#[test]
fn an_approver_revokes_but_a_stranger_does_not() {
    let mut scene = Scene::new();
    let gov = governance();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    pending(flow.request(&scene.review(T0), &ask("e1", 2 * HOUR), None).unwrap());
    scene.grants = flow.approve(&scene.review(T0 + 1), &admin("bia"), "e1").unwrap().grants;

    let stranger = Subject::user("caio").with_role_in("member", org());
    let error = flow.revoke(&scene.review(T0 + 5), &stranger, "e1", None).unwrap_err();
    assert!(matches!(error, ApprovalError::Refused(_)), "veio {error:?}");
    assert_eq!(flow.active(T0 + 6).unwrap().len(), 1);

    flow.revoke(&scene.review(T0 + 10), &admin("bia"), "e1", None).unwrap();
    assert!(flow.active(T0 + 11).unwrap().is_empty());
}

#[test]
fn an_expired_elevation_cannot_be_revoked() {
    let scene = Scene::new();
    let gov = governance();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    pending(flow.request(&scene.review(T0), &ask("e1", HOUR), None).unwrap());
    flow.approve(&scene.review(T0), &admin("bia"), "e1").unwrap();
    let error = flow.revoke(&scene.review(T0 + HOUR), &ana(), "e1", None).unwrap_err();
    assert_eq!(violations_of(error), ["elevation_state"]);
}

#[test]
fn break_glass_applies_at_once_marked_and_with_a_pending_review() {
    let scene = Scene::new();
    let (gov, log) = audited(AuditLevel::Forensic);
    let (policy, store) = (break_glass_policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    let request = ask("e1", HOUR).break_glass();
    let Elevated::Active(approved) = flow.request(&scene.review(T0), &request, None).unwrap() else {
        panic!("break-glass deveria aplicar na hora")
    };
    let grant = approved
        .grants
        .iter()
        .find(|g| g.id == "elevation:e1")
        .expect("grant da elevação");
    assert_eq!(grant.valid_until, Some(T0 + HOUR));
    let info = approved.request.elevation.as_ref().unwrap();
    assert!(info.break_glass);
    assert_eq!(info.review, Some(ReviewState::Pending));
    assert_eq!(flow.active(T0 + 1).unwrap().len(), 1);
    assert_eq!(flow.pending_reviews().unwrap().len(), 1);

    let records = log.records();
    assert!(!records.is_empty());
    verify_chain(&records).unwrap();
    assert!(records.iter().all(|r| r.level == AuditLevel::Forensic));
    assert!(records.iter().any(|r| r.meta.contains_key("break_glass")));

    let closed = flow
        .close_review(&scene.review(T0 + 60), &admin("bia"), "e1", "uso legítimo")
        .unwrap();
    assert!(matches!(
        closed.elevation.unwrap().review,
        Some(ReviewState::Closed { .. })
    ));
    assert!(flow.pending_reviews().unwrap().is_empty());
    assert!(log.records().iter().any(|r| r.action == AuditAction::ElevationReview));
}

#[test]
fn the_actor_of_a_break_glass_does_not_close_its_review() {
    let scene = Scene::new();
    let (gov, _log) = audited(AuditLevel::Forensic);
    let (policy, store) = (break_glass_policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);
    let author = admin("ana");

    let request = ElevationRequest::new("e1", author.clone(), edit(), HOUR)
        .justified("fogo")
        .break_glass();
    flow.request(&scene.review(T0), &request, None).unwrap();
    let error = flow
        .close_review(&scene.review(T0 + 1), &author, "e1", "ok")
        .unwrap_err();
    assert_eq!(violations_of(error), ["elevation_review"]);
    assert_eq!(flow.pending_reviews().unwrap().len(), 1);
}

#[test]
fn break_glass_is_refused_where_the_policy_forbids_it() {
    let scene = Scene::new();
    let (gov, _log) = audited(AuditLevel::Forensic);
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    let error = flow
        .request(&scene.review(T0), &ask("e1", HOUR).break_glass(), None)
        .unwrap_err();
    assert_eq!(violations_of(error), ["break_glass"]);
    assert!(store.list().unwrap().is_empty());
    assert!(flow.active(T0 + 1).unwrap().is_empty());
}

#[test]
fn break_glass_has_a_shorter_cap_than_the_rule() {
    let scene = Scene::new();
    let (gov, _log) = audited(AuditLevel::Forensic);
    let (policy, store) = (break_glass_policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    let error = flow
        .request(&scene.review(T0), &ask("e1", HOUR + 1).break_glass(), None)
        .unwrap_err();
    assert_eq!(violations_of(error), ["elevation_duration"]);
}

#[test]
fn break_glass_needs_a_justification() {
    let scene = Scene::new();
    let (gov, _log) = audited(AuditLevel::Forensic);
    let policy = ElevationPolicy::new()
        .with(ElevationRule::new(edit().key(), 4 * HOUR, "org.manage", project()).allowing_break_glass(HOUR));
    let store = MemoryPendingStore::new();
    let flow = Elevations::new(&gov, &policy, &store);

    let request = ElevationRequest::new("e1", ana(), edit(), HOUR).break_glass();
    let error = flow.request(&scene.review(T0), &request, None).unwrap_err();
    assert_eq!(violations_of(error), ["elevation_justification"]);
}

#[test]
fn a_failing_sink_denies_break_glass_whatever_the_fail_mode() {
    let scene = Scene::new();
    let sink = |_: &strig::AuditRecord| Err(strig::AuditError::Sink("fora do ar".into()));
    let auditor = Auditor::new(AuditLevel::Forensic, Arc::new(sink)).with_fail_mode(FailMode::Open);
    let gov = governance().audited(Arc::new(auditor));
    let (policy, store) = (break_glass_policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store).fail_mode(FailMode::Open);

    let error = flow
        .request(&scene.review(T0), &ask("e1", HOUR).break_glass(), None)
        .unwrap_err();
    assert_eq!(violations_of(error), ["audit"]);
    assert!(store.list().unwrap().is_empty());
    assert!(flow.active(T0 + 1).unwrap().is_empty());
}

#[test]
fn break_glass_needs_a_forensic_auditor() {
    let scene = Scene::new();
    let (policy, store) = (break_glass_policy(), MemoryPendingStore::new());

    let (standard, _log) = audited(AuditLevel::Standard);
    let error = Elevations::new(&standard, &policy, &store)
        .request(&scene.review(T0), &ask("e1", HOUR).break_glass(), None)
        .unwrap_err();
    assert_eq!(violations_of(error), ["break_glass_audit"]);

    let bare = governance();
    let error = Elevations::new(&bare, &policy, &store)
        .request(&scene.review(T0), &ask("e2", HOUR).break_glass(), None)
        .unwrap_err();
    assert_eq!(violations_of(error), ["break_glass_audit"]);
}

#[test]
fn a_refused_request_is_in_the_trail() {
    let scene = Scene::new();
    let (gov, log) = audited(AuditLevel::Standard);
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    flow.request(&scene.review(T0), &ask("e1", 9 * HOUR), None).unwrap_err();
    assert_eq!(log.records().len(), 1);
}

#[test]
fn a_pending_elevation_that_is_never_approved_expires() {
    let scene = Scene::new();
    let gov = governance();
    let (policy, store) = (policy(), MemoryPendingStore::new());
    let flow = Elevations::new(&gov, &policy, &store);

    pending(
        flow.request(&scene.review(T0), &ask("e1", HOUR), Some(T0 + 100))
            .unwrap(),
    );
    let expired = flow.expire_due(T0 + 100, &Attributes::new()).unwrap();
    assert_eq!(expired.len(), 1);
    let error = flow.approve(&scene.review(T0 + 101), &admin("bia"), "e1").unwrap_err();
    assert!(!matches!(error, ApprovalError::Refused(ref v) if v.is_empty()));
}
