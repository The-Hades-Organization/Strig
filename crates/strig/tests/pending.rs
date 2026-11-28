//! Fluxo de pedido pendente: propor, aprovar ou recusar por outro ator, expirar e auditar.

mod support;

use strig::{
    ApprovalError, ApprovalPolicy, Approvals, Attributes, CatalogConformance, Governance, Grant, MemoryPendingStore,
    Mutation, MutationKind, NoSelfManagement, PendingError, PendingStatus, PendingStore, Proposed, RequirePermission,
    Review, RoleAssignment, Subject,
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

fn pending_of(proposed: Proposed) -> strig::PendingRequest {
    match proposed {
        Proposed::Pending(request) => request,
        Proposed::Applied(_) => panic!("esperava um pedido pendente"),
    }
}

fn violations_of(error: ApprovalError) -> Vec<String> {
    match error {
        ApprovalError::Refused(violations) => violations.into_iter().map(|v| v.invariant).collect(),
        other => panic!("esperava recusa, veio {other:?}"),
    }
}

#[test]
fn a_change_the_policy_covers_waits_and_applies_nothing() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);

    let request = pending_of(
        flow.propose(&scene.review(T0), &admin("ana"), &add("m-edit"), "r1", Some(T0 + 500))
            .unwrap(),
    );
    assert_eq!(request.id, "r1");
    assert_eq!(request.status, PendingStatus::Pending);
    assert_eq!(request.requested_at, T0);
    assert_eq!(request.expires_at, Some(T0 + 500));
    assert_eq!(flow.pending(T0).unwrap(), vec![request]);
}

#[test]
fn a_change_the_policy_does_not_cover_applies_at_once() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);

    let remove = Mutation::Remove {
        id: "member-view".into(),
    };
    let Proposed::Applied(grants) = flow
        .propose(&scene.review(T0), &admin("ana"), &remove, "r1", None)
        .unwrap()
    else {
        panic!("sem regra para remove, aplica na hora");
    };
    assert_eq!(grants.len(), 1);
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn a_proposal_the_invariants_refuse_never_becomes_a_request() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);

    let member = Subject::user("bia").with_role_in("member", org());
    let error = flow
        .propose(&scene.review(T0), &member, &add("m-edit"), "r1", None)
        .unwrap_err();
    assert!(violations_of(error).contains(&"require_permission".to_string()));
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn proposal_rejects_empty_id_past_expiry_and_duplicate_id() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);
    let ana = admin("ana");

    let empty = flow.propose(&scene.review(T0), &ana, &add("a"), "", None).unwrap_err();
    assert_eq!(violations_of(empty), ["mutation"]);
    let past = flow
        .propose(&scene.review(T0), &ana, &add("a"), "r1", Some(T0))
        .unwrap_err();
    assert_eq!(violations_of(past), ["mutation"]);

    flow.propose(&scene.review(T0), &ana, &add("a"), "r1", None).unwrap();
    let again = flow
        .propose(&scene.review(T0), &ana, &add("b"), "r1", None)
        .unwrap_err();
    assert_eq!(again, ApprovalError::Store(PendingError::Duplicate("r1".into())));
}

#[test]
fn another_actor_with_the_permission_approves_and_the_change_applies() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);
    flow.propose(&scene.review(T0), &admin("ana"), &add("m-edit"), "r1", None)
        .unwrap();

    let approved = flow.approve(&scene.review(T0 + 10), &admin("caio"), "r1").unwrap();
    assert_eq!(approved.grants.len(), 3);
    assert_eq!(
        approved.request.status,
        PendingStatus::Approved {
            by: "caio".into(),
            at: T0 + 10
        }
    );
    assert!(flow.pending(T0 + 10).unwrap().is_empty());
}

#[test]
fn the_author_never_approves_their_own_request() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);
    let ana = admin("ana");
    flow.propose(&scene.review(T0), &ana, &add("m-edit"), "r1", None)
        .unwrap();

    let error = flow.approve(&scene.review(T0), &ana, "r1").unwrap_err();
    assert_eq!(violations_of(error), ["no_self_approval"]);
    let same_id_other_kind = Subject::of_kind("service", "ana").with_role_in("admin", org());
    let error = flow.approve(&scene.review(T0), &same_id_other_kind, "r1").unwrap_err();
    assert_eq!(violations_of(error), ["no_self_approval"]);
    let error = flow.reject(&scene.review(T0), &ana, "r1", "desisti").unwrap_err();
    assert_eq!(violations_of(error), ["no_self_approval"]);
    assert_eq!(flow.pending(T0).unwrap().len(), 1);
}

#[test]
fn an_approver_without_the_permission_is_refused_and_the_request_stays() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);
    flow.propose(&scene.review(T0), &admin("ana"), &add("m-edit"), "r1", None)
        .unwrap();

    let member = Subject::user("bia").with_role_in("member", org());
    let error = flow.approve(&scene.review(T0), &member, "r1").unwrap_err();
    assert_eq!(violations_of(error), ["require_approval_permission"]);
    let anonymous = Subject::anonymous();
    assert!(flow.approve(&scene.review(T0), &anonymous, "r1").is_err());
    assert!(store.get("r1").unwrap().unwrap().is_pending());
}

#[test]
fn approval_judges_the_invariants_again_over_the_current_state() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);
    flow.propose(&scene.review(T0), &admin("ana"), &add("m-edit"), "r1", None)
        .unwrap();

    let mut changed = Scene::new();
    changed
        .grants
        .push(role_grant("m-edit", "member", "project.view", true, at_org()));
    let error = flow.approve(&changed.review(T0 + 1), &admin("caio"), "r1").unwrap_err();
    assert_eq!(violations_of(error), ["mutation"]);
    assert!(store.get("r1").unwrap().unwrap().is_pending());

    let approved = flow.approve(&scene.review(T0 + 2), &admin("caio"), "r1").unwrap();
    assert_eq!(approved.grants.len(), 3);
}

#[test]
fn approval_judges_the_change_as_the_author_not_as_the_approver() {
    let mut scene = Scene::new();
    scene
        .grants
        .push(role_grant("owner-manage", "owner", "org.manage", true, at_org()));
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);
    flow.propose(&scene.review(T0), &admin("ana"), &add("m-edit"), "r1", None)
        .unwrap();

    let mut changed = Scene::new();
    changed.grants = vec![role_grant("owner-manage", "owner", "org.manage", true, at_org())];
    let owner = Subject::user("caio").with_role_in("owner", org());
    let error = flow.approve(&changed.review(T0 + 1), &owner, "r1").unwrap_err();
    assert!(violations_of(error).contains(&"require_permission".to_string()));
    assert!(store.get("r1").unwrap().unwrap().is_pending());
}

#[test]
fn a_refusal_carries_its_reason_and_closes_the_request() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);
    flow.propose(&scene.review(T0), &admin("ana"), &add("m-edit"), "r1", None)
        .unwrap();

    let empty = flow.reject(&scene.review(T0), &admin("caio"), "r1", "  ").unwrap_err();
    assert_eq!(violations_of(empty), ["mutation"]);
    let request = flow
        .reject(&scene.review(T0 + 5), &admin("caio"), "r1", "fora da janela de mudança")
        .unwrap();
    assert_eq!(
        request.status,
        PendingStatus::Rejected {
            by: "caio".into(),
            at: T0 + 5,
            reason: "fora da janela de mudança".into()
        }
    );
    let again = flow.approve(&scene.review(T0 + 6), &admin("caio"), "r1").unwrap_err();
    assert_eq!(again, ApprovalError::Store(PendingError::NotPending("r1".into())));
    let unknown = flow.approve(&scene.review(T0 + 6), &admin("caio"), "nope").unwrap_err();
    assert_eq!(unknown, ApprovalError::Store(PendingError::Unknown("nope".into())));
}

#[test]
fn a_request_expires_and_cannot_be_decided_afterwards() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);
    let ana = admin("ana");
    flow.propose(&scene.review(T0), &ana, &add("a"), "due", Some(T0 + 100))
        .unwrap();
    flow.propose(&scene.review(T0), &ana, &add("b"), "later", Some(T0 + 900))
        .unwrap();
    flow.propose(&scene.review(T0), &ana, &add("c"), "never", None).unwrap();

    assert_eq!(flow.pending(T0 + 100).unwrap().len(), 2);
    let expired = flow.expire_due(T0 + 100, &scene.meta).unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].status, PendingStatus::Expired { at: T0 + 100 });
    assert!(flow.expire_due(T0 + 100, &scene.meta).unwrap().is_empty());

    let late = flow
        .approve(&scene.review(T0 + 900), &admin("caio"), "later")
        .unwrap_err();
    assert_eq!(late, ApprovalError::Expired("later".into()));
    assert!(matches!(
        store.get("later").unwrap().unwrap().status,
        PendingStatus::Expired { at } if at == T0 + 900
    ));
    let closed = flow
        .approve(&scene.review(T0 + 900), &admin("caio"), "due")
        .unwrap_err();
    assert_eq!(closed, ApprovalError::Store(PendingError::NotPending("due".into())));
    assert!(flow.approve(&scene.review(T0 + 5_000), &admin("caio"), "never").is_ok());
}

#[test]
fn a_role_change_is_a_request_too_and_keeps_the_subject_to_write() {
    let scene = Scene::new();
    let (gov, store) = (governance(), MemoryPendingStore::new());
    let policy = ApprovalPolicy::new().require_all("org.manage", project());
    let flow = Approvals::new(&gov, &policy, &store);
    let target = Subject::user("dani");
    let change = Mutation::AssignRole {
        subject: target.clone(),
        role: RoleAssignment::new("member"),
    };
    let known = {
        let mut s = Scene::new();
        s.grants
            .push(role_grant("m-role", "member", "project.view", true, at_org()));
        s
    };
    flow.propose(&known.review(T0), &admin("ana"), &change, "r1", None)
        .unwrap();
    let approved = flow.approve(&known.review(T0), &admin("caio"), "r1").unwrap();
    assert_eq!(approved.request.mutation.subject_after().unwrap().roles.len(), 1);
    assert_eq!(approved.grants.len(), known.grants.len());
    let _ = scene;
}

#[test]
fn distinct_roles_refuse_an_approver_who_shares_a_role_with_the_author() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store).with_distinct_roles();
    flow.propose(&scene.review(T0), &admin("ana"), &add("m-edit"), "r1", None)
        .unwrap();

    let error = flow.approve(&scene.review(T0), &admin("caio"), "r1").unwrap_err();
    assert_eq!(violations_of(error), ["distinct_approver_roles"]);
    assert_eq!(flow.pending(T0).unwrap().len(), 1);
}

#[test]
fn distinct_roles_accept_an_approver_with_another_role() {
    let mut scene = Scene::new();
    scene
        .grants
        .push(role_grant("auditor-manage", "auditor", "org.manage", true, at_org()));
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store).with_distinct_roles();
    flow.propose(&scene.review(T0), &admin("ana"), &add("m-edit"), "r1", None)
        .unwrap();

    let auditor = Subject::user("caio").with_role_in("auditor", org());
    assert!(flow.approve(&scene.review(T0), &auditor, "r1").is_ok());
}

#[test]
fn without_distinct_roles_two_admins_still_approve_each_other() {
    let scene = Scene::new();
    let (gov, policy, store) = (governance(), policy(), MemoryPendingStore::new());
    let flow = Approvals::new(&gov, &policy, &store);
    flow.propose(&scene.review(T0), &admin("ana"), &add("m-edit"), "r1", None)
        .unwrap();
    assert!(flow.approve(&scene.review(T0), &admin("caio"), "r1").is_ok());
}
