//! Posse exclusiva: disputa por prioridade, preempção autorizada, prazo e renovação.
#![cfg(feature = "exclusive")]

use themis::{
    Acquisition, Anchor, Catalog, Claim, Context, Engine, ExclusiveError, ExclusivePermissions, ExclusiveRegistry,
    Grant, ObjectRef, PermissionDef, Preemption, Resource, Subject, SubjectMatcher, TargetSelector, Terms,
};

const TTL: u64 = 1_000;

fn catalog() -> Catalog {
    Catalog::builder()
        .target_kinds(["document"])
        .broad_target("org")
        .permission(PermissionDef::new("exclusive.hold").targets(["org", "document"]))
        .permission(PermissionDef::new("exclusive.preempt").targets(["org", "document"]))
        .build()
        .expect("catálogo")
}

fn engine() -> Engine {
    Engine::builder(catalog()).build().expect("motor")
}

fn grants() -> Vec<Grant> {
    let org = Anchor::new("org", "o1");
    let at_org = TargetSelector::exact("org", "o1");
    let allow = |id: &str, role: &str, permission: &str| {
        Grant::allow(id, SubjectMatcher::role(role), permission, at_org.clone()).scoped(org.clone())
    };
    vec![
        allow("g1", "editor", "exclusive.hold"),
        allow("g2", "supervisor", "exclusive.hold"),
        allow("g3", "supervisor", "exclusive.preempt"),
    ]
}

fn org() -> Anchor {
    Anchor::new("org", "o1")
}

fn editor(id: &str) -> Subject {
    Subject::user(id).with_role_in("editor", org())
}

fn supervisor(id: &str) -> Subject {
    Subject::user(id).with_role_in("supervisor", org())
}

fn document() -> Resource {
    Resource::new("document", "d1").within("org", "o1")
}

fn doc_ref() -> ObjectRef {
    ObjectRef::new("document", "d1")
}

fn user(id: &str) -> ObjectRef {
    ObjectRef::new("user", id)
}

fn terms(priority: i64) -> Terms {
    Terms::new(priority, TTL)
}

#[test]
fn free_resource_is_granted_and_reports_its_holder() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();

    let outcome = registry
        .acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(1), 100)
        .unwrap();

    assert_eq!(outcome, Acquisition::Granted);
    let lease = registry.holder(&doc_ref(), 100).unwrap().unwrap();
    assert_eq!(lease.holder, user("alice"));
    assert_eq!(lease.priority, 1);
    assert_eq!(lease.expires_at, 100 + TTL);
}

#[test]
fn equal_priority_never_preempts() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire_checked(&engine, &ctx, &supervisor("alice"), &document(), terms(5), 0)
        .unwrap();

    let outcome = registry
        .acquire_checked(&engine, &ctx, &supervisor("bob"), &document(), terms(5), 10)
        .unwrap();

    assert!(matches!(outcome, Acquisition::Busy { holder } if holder.holder == user("alice")));
    let kept = registry.holder(&doc_ref(), 10).unwrap().unwrap();
    assert_eq!((kept.holder, kept.priority, kept.expires_at), (user("alice"), 5, TTL));
}

#[test]
fn lower_priority_is_busy_even_with_the_preemption_permission() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(5), 0)
        .unwrap();

    let outcome = registry
        .acquire_checked(&engine, &ctx, &supervisor("bob"), &document(), terms(1), 10)
        .unwrap();

    assert!(matches!(outcome, Acquisition::Busy { .. }));
    assert_eq!(registry.holder(&doc_ref(), 10).unwrap().unwrap().holder, user("alice"));
}

#[test]
fn higher_priority_with_permission_preempts_and_returns_the_previous_holder() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(1), 0)
        .unwrap();

    let outcome = registry
        .acquire_checked(&engine, &ctx, &supervisor("bob"), &document(), terms(9), 10)
        .unwrap();

    match outcome {
        Acquisition::Preempted { previous } => assert_eq!((previous.holder, previous.priority), (user("alice"), 1)),
        other => panic!("esperava Preempted, veio {other:?}"),
    }
    let lease = registry.holder(&doc_ref(), 10).unwrap().unwrap();
    assert_eq!(
        (lease.holder, lease.priority, lease.expires_at),
        (user("bob"), 9, 10 + TTL)
    );
}

#[test]
fn higher_priority_without_preemption_permission_is_refused_and_holder_stays() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(1), 0)
        .unwrap();

    let outcome = registry.acquire_checked(&engine, &ctx, &editor("bob"), &document(), terms(9), 10);

    assert!(matches!(outcome, Err(ExclusiveError::Denied(permission)) if permission == "exclusive.preempt"));
    assert_eq!(registry.holder(&doc_ref(), 10).unwrap().unwrap().holder, user("alice"));
}

#[test]
fn acquiring_without_the_hold_permission_is_refused() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();

    let outcome = registry.acquire_checked(&engine, &ctx, &Subject::user("mallory"), &document(), terms(100), 0);

    assert!(matches!(outcome, Err(ExclusiveError::Denied(permission)) if permission == "exclusive.hold"));
    assert!(registry.holder(&doc_ref(), 0).unwrap().is_none());
}

#[test]
fn anonymous_subject_and_resource_without_identity_are_refused() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();

    let anonymous = registry.acquire_checked(&engine, &ctx, &Subject::anonymous(), &document(), terms(1), 0);
    let global = registry.acquire_checked(&engine, &ctx, &editor("alice"), &Resource::global(), terms(1), 0);

    assert!(matches!(anonymous, Err(ExclusiveError::AnonymousSubject)));
    assert!(matches!(global, Err(ExclusiveError::UnidentifiedResource)));
}

#[test]
fn permission_names_are_configurable_and_validated_against_the_catalog() {
    let engine = engine();
    let registry = ExclusiveRegistry::default().with_permissions(ExclusivePermissions {
        hold: "exclusive.hold".into(),
        preempt: "exclusive.take_over".into(),
    });

    assert!(matches!(
        registry.validate(&engine),
        Err(ExclusiveError::UnknownPermission(name)) if name == "exclusive.take_over"
    ));
    assert!(ExclusiveRegistry::default().validate(&engine).is_ok());
}

#[test]
fn expired_lease_frees_the_resource() {
    let mut registry = ExclusiveRegistry::default();
    let first = Claim::new(doc_ref(), user("alice"), terms(9));
    registry.acquire(&first, 0, Preemption::Forbidden).unwrap();

    assert!(registry.holder(&doc_ref(), TTL - 1).unwrap().is_some());
    assert!(registry.holder(&doc_ref(), TTL).unwrap().is_none());

    let second = Claim::new(doc_ref(), user("bob"), terms(1));
    let outcome = registry.acquire(&second, TTL, Preemption::Forbidden).unwrap();
    assert_eq!(outcome, Acquisition::Granted);
}

#[test]
fn expire_removes_only_the_leases_that_ran_out() {
    let mut registry = ExclusiveRegistry::default();
    let short = Claim::new(ObjectRef::new("document", "short"), user("alice"), Terms::new(1, 10));
    let long = Claim::new(ObjectRef::new("document", "long"), user("alice"), Terms::new(1, 100));
    registry.acquire(&short, 0, Preemption::Forbidden).unwrap();
    registry.acquire(&long, 0, Preemption::Forbidden).unwrap();

    let expired = registry.expire(50).unwrap();

    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].resource, ObjectRef::new("document", "short"));
    assert!(registry.expire(50).unwrap().is_empty());
    assert!(
        registry
            .holder(&ObjectRef::new("document", "long"), 50)
            .unwrap()
            .is_some()
    );
}

#[test]
fn renew_extends_the_lease_and_keeps_the_priority() {
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire(
            &Claim::new(doc_ref(), user("alice"), terms(7)),
            0,
            Preemption::Forbidden,
        )
        .unwrap();

    let renewed = registry.renew(&doc_ref(), &user("alice"), 900, TTL).unwrap();

    assert_eq!(renewed.expires_at, 900 + TTL);
    assert_eq!(renewed.priority, 7);
    assert!(registry.holder(&doc_ref(), TTL + 500).unwrap().is_some());
}

#[test]
fn checked_renew_needs_the_ownership_permission_at_the_instant() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(3), 0)
        .unwrap();

    let renewed = registry
        .renew_checked(&engine, &ctx, &editor("alice"), &document(), 400, TTL)
        .unwrap();
    assert_eq!((renewed.expires_at, renewed.priority), (400 + TTL, 3));

    // The grant was revoked: the lease is not renewed and stays as it was.
    let revoked: Vec<Grant> = grants.iter().filter(|g| g.id != "g1").cloned().collect();
    let after = Context::new(&revoked);
    assert!(matches!(
        registry.renew_checked(&engine, &after, &editor("alice"), &document(), 500, TTL),
        Err(ExclusiveError::Denied(permission)) if permission == "exclusive.hold"
    ));
    assert_eq!(registry.holder(&doc_ref(), 500).unwrap().unwrap().expires_at, 400 + TTL);
}

#[test]
fn checked_renew_judges_the_grant_window_at_now_not_at_the_context_instant() {
    let (engine, mut grants) = (engine(), grants());
    grants[0] = grants[0].clone().valid_until(1_200);
    let ctx = Context::new(&grants).at(100);
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(1), 100)
        .unwrap();

    // The context still says 100, but the renewal happens at 1_300: the window is over.
    assert!(matches!(
        registry.renew_checked(&engine, &ctx, &editor("alice"), &document(), 1_000, 500),
        Ok(_)
    ));
    assert!(matches!(
        registry.renew_checked(&engine, &ctx, &editor("alice"), &document(), 1_300, 500),
        Err(ExclusiveError::Denied(_))
    ));
}

#[test]
fn checked_renew_refuses_anonymous_unidentified_and_foreign_holders() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(1), 0)
        .unwrap();

    let anonymous = Subject::anonymous();
    assert!(matches!(
        registry.renew_checked(&engine, &ctx, &anonymous, &document(), 10, TTL),
        Err(ExclusiveError::AnonymousSubject)
    ));
    assert!(matches!(
        registry.renew_checked(&engine, &ctx, &editor("bob"), &document(), 10, TTL),
        Err(ExclusiveError::NotHolder { .. })
    ));
    assert!(matches!(
        registry.renew_checked(&engine, &ctx, &editor("alice"), &document(), 10, 0),
        Err(ExclusiveError::ZeroTtl)
    ));
}

#[test]
fn renew_fails_after_expiry_for_another_holder_and_with_zero_ttl() {
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire(
            &Claim::new(doc_ref(), user("alice"), terms(1)),
            0,
            Preemption::Forbidden,
        )
        .unwrap();

    assert!(matches!(
        registry.renew(&doc_ref(), &user("bob"), 10, TTL),
        Err(ExclusiveError::NotHolder { holder, .. }) if holder == user("alice")
    ));
    assert!(matches!(
        registry.renew(&doc_ref(), &user("alice"), 10, 0),
        Err(ExclusiveError::ZeroTtl)
    ));
    assert!(matches!(
        registry.renew(&doc_ref(), &user("alice"), TTL, TTL),
        Err(ExclusiveError::NotHeld(_))
    ));
}

#[test]
fn only_the_holder_releases() {
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire(
            &Claim::new(doc_ref(), user("alice"), terms(1)),
            0,
            Preemption::Forbidden,
        )
        .unwrap();

    assert!(matches!(
        registry.release(&doc_ref(), &user("bob"), 5),
        Err(ExclusiveError::NotHolder { .. })
    ));
    let released = registry.release(&doc_ref(), &user("alice"), 5).unwrap();
    assert_eq!(released.holder, user("alice"));
    assert!(registry.holder(&doc_ref(), 5).unwrap().is_none());
    assert!(matches!(
        registry.release(&doc_ref(), &user("alice"), 5),
        Err(ExclusiveError::NotHeld(_))
    ));
}

#[test]
fn holder_reacquiring_replaces_its_own_lease() {
    let mut registry = ExclusiveRegistry::default();
    let claim = Claim::new(doc_ref(), user("alice"), terms(1));
    registry.acquire(&claim, 0, Preemption::Forbidden).unwrap();

    let outcome = registry.acquire(&claim, 500, Preemption::Forbidden).unwrap();

    assert_eq!(outcome, Acquisition::Granted);
    assert_eq!(registry.holder(&doc_ref(), 500).unwrap().unwrap().expires_at, 500 + TTL);
}

#[test]
fn expired_lease_does_not_ask_for_the_preemption_permission() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(1), 0)
        .unwrap();

    let outcome = registry
        .acquire_checked(&engine, &ctx, &editor("bob"), &document(), terms(9), TTL)
        .unwrap();

    assert_eq!(outcome, Acquisition::Granted);
}

#[test]
fn zero_ttl_through_the_checked_path_leaves_no_lease() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();

    let outcome = registry.acquire_checked(&engine, &ctx, &editor("alice"), &document(), Terms::new(1, 0), 0);

    assert!(matches!(outcome, Err(ExclusiveError::ZeroTtl)));
    assert!(registry.holder(&doc_ref(), 0).unwrap().is_none());
}

#[test]
fn unchecked_acquire_with_equal_priority_is_busy_even_when_preemption_is_allowed() {
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire(
            &Claim::new(doc_ref(), user("alice"), terms(5)),
            0,
            Preemption::Forbidden,
        )
        .unwrap();

    let outcome = registry
        .acquire(&Claim::new(doc_ref(), user("bob"), terms(5)), 1, Preemption::Allowed)
        .unwrap();

    assert!(matches!(outcome, Acquisition::Busy { .. }));
}

#[test]
fn lease_runs_out_exactly_at_its_expiry_and_expire_lists_every_one_in_order() {
    let mut registry = ExclusiveRegistry::default();
    for id in ["b", "a"] {
        let claim = Claim::new(ObjectRef::new("document", id), user("alice"), Terms::new(1, 10));
        registry.acquire(&claim, 0, Preemption::Forbidden).unwrap();
    }

    assert!(registry.expire(9).unwrap().is_empty());
    let expired = registry.expire(10).unwrap();

    let ids: Vec<_> = expired.iter().map(|lease| lease.resource.id.as_str()).collect();
    assert_eq!(ids, ["a", "b"]);
}

#[test]
fn releasing_an_expired_lease_reports_not_held() {
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire(
            &Claim::new(doc_ref(), user("alice"), terms(1)),
            0,
            Preemption::Forbidden,
        )
        .unwrap();

    assert!(matches!(
        registry.release(&doc_ref(), &user("alice"), TTL),
        Err(ExclusiveError::NotHeld(_))
    ));
}

#[test]
fn holder_raising_its_own_priority_needs_the_preemption_permission() {
    let (engine, grants) = (engine(), grants());
    let ctx = Context::new(&grants);
    let mut registry = ExclusiveRegistry::default();
    registry
        .acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(1), 0)
        .unwrap();

    let raised = registry.acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(i64::MAX), 5);

    assert!(matches!(raised, Err(ExclusiveError::Denied(permission)) if permission == "exclusive.preempt"));
    assert_eq!(registry.holder(&doc_ref(), 5).unwrap().unwrap().priority, 1);
    let same = registry.acquire_checked(&engine, &ctx, &editor("alice"), &document(), terms(1), 5);
    assert_eq!(same.unwrap(), Acquisition::Granted);
}

#[test]
fn max_ttl_caps_acquisition_and_renewal() {
    let mut registry = ExclusiveRegistry::default().with_max_ttl(TTL);
    let too_long = Claim::new(doc_ref(), user("alice"), Terms::new(1, TTL + 1));

    assert!(matches!(
        registry.acquire(&too_long, 0, Preemption::Forbidden),
        Err(ExclusiveError::TtlTooLong(max)) if max == TTL
    ));
    registry
        .acquire(
            &Claim::new(doc_ref(), user("alice"), terms(1)),
            0,
            Preemption::Forbidden,
        )
        .unwrap();
    assert!(matches!(
        registry.renew(&doc_ref(), &user("alice"), 1, u64::MAX),
        Err(ExclusiveError::TtlTooLong(_))
    ));
}
