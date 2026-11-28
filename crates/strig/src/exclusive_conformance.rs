//! Conformance battery for [`ExclusiveStore`] implementations.
//!
//! Every store must give the same answers as [`crate::MemoryExclusiveStore`]. An adapter crate calls
//! [`run`] with a closure that returns a store over an empty namespace, once per scenario, and gets the
//! scenarios the in-memory store passes. The scenarios panic on the first difference.

use crate::exclusive::{
    Acquisition, Claim, ExclusiveError, ExclusiveRegistry, ExclusiveStore, Lease, Preemption, Terms,
};
use crate::resource::ObjectRef;

const TTL: u64 = 1_000;

fn doc(id: &str) -> ObjectRef {
    ObjectRef::new("document", id)
}

fn user(id: &str) -> ObjectRef {
    ObjectRef::new("user", id)
}

fn claim(resource: &ObjectRef, holder: &str, priority: i64, ttl_ms: u64) -> Claim {
    Claim::new(resource.clone(), user(holder), Terms::new(priority, ttl_ms))
}

type Scenario<S> = fn(&mut ExclusiveRegistry<S>);

/// Runs every scenario, each over a store from `fresh`.
///
/// # Panics
/// When a store answers differently from the in-memory one.
pub fn run<S: ExclusiveStore>(mut fresh: impl FnMut() -> S) {
    let scenarios: [(&str, Scenario<S>); 15] = [
        ("free resource is granted", free_resource_is_granted),
        ("equal priority never preempts", equal_priority_never_preempts),
        ("lower priority is busy", lower_priority_is_busy),
        ("preemption returns the previous lease", preemption_returns_previous),
        (
            "preemption needs permission to be allowed",
            preemption_forbidden_is_busy,
        ),
        ("expired lease frees the resource", expired_lease_frees_the_resource),
        ("expiry is exactly at expires_at", expiry_is_exact),
        ("renew extends and keeps priority", renew_extends),
        ("renew refuses other holder, expired and zero ttl", renew_refusals),
        ("only the holder releases", only_the_holder_releases),
        ("holder reacquiring replaces its lease", reacquire_replaces),
        ("expire removes only what ran out, in order", expire_in_order),
        ("extreme priorities compare exactly", extreme_priorities),
        (
            "resources with separators in the identity do not collide",
            identities_do_not_collide,
        ),
        ("an empty store reads nothing", empty_store_reads_nothing),
    ];
    for (name, scenario) in scenarios {
        let mut registry = ExclusiveRegistry::new(fresh());
        eprintln!("exclusive conformance: {name}");
        scenario(&mut registry);
    }
    eprintln!("exclusive conformance: max ttl caps acquisition and renewal");
    max_ttl(fresh());
}

fn free_resource_is_granted<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    let outcome = registry.acquire(&claim(&doc("d1"), "alice", 1, TTL), 100, Preemption::Forbidden);
    assert_eq!(outcome.unwrap(), Acquisition::Granted);
    let lease = registry.holder(&doc("d1"), 100).unwrap().unwrap();
    assert_eq!(
        lease,
        Lease {
            resource: doc("d1"),
            holder: user("alice"),
            priority: 1,
            acquired_at: 100,
            expires_at: 100 + TTL,
        }
    );
    assert!(registry.holder(&doc("other"), 100).unwrap().is_none());
}

fn equal_priority_never_preempts<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    registry
        .acquire(&claim(&doc("d1"), "alice", 5, TTL), 0, Preemption::Forbidden)
        .unwrap();
    let outcome = registry
        .acquire(&claim(&doc("d1"), "bob", 5, TTL), 10, Preemption::Allowed)
        .unwrap();
    assert!(matches!(outcome, Acquisition::Busy { holder } if holder.holder == user("alice")));
    let kept = registry.holder(&doc("d1"), 10).unwrap().unwrap();
    assert_eq!((kept.holder, kept.priority, kept.expires_at), (user("alice"), 5, TTL));
}

fn lower_priority_is_busy<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    registry
        .acquire(&claim(&doc("d1"), "alice", 5, TTL), 0, Preemption::Forbidden)
        .unwrap();
    let outcome = registry
        .acquire(&claim(&doc("d1"), "bob", 1, TTL), 10, Preemption::Allowed)
        .unwrap();
    assert!(matches!(outcome, Acquisition::Busy { .. }));
    assert_eq!(registry.holder(&doc("d1"), 10).unwrap().unwrap().holder, user("alice"));
}

fn preemption_returns_previous<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    registry
        .acquire(&claim(&doc("d1"), "alice", 1, TTL), 0, Preemption::Forbidden)
        .unwrap();
    let outcome = registry
        .acquire(&claim(&doc("d1"), "bob", 9, TTL), 10, Preemption::Allowed)
        .unwrap();
    match outcome {
        Acquisition::Preempted { previous } => {
            assert_eq!(
                (previous.holder, previous.priority, previous.expires_at),
                (user("alice"), 1, TTL)
            );
        }
        other => panic!("expected Preempted, got {other:?}"),
    }
    let lease = registry.holder(&doc("d1"), 10).unwrap().unwrap();
    assert_eq!(
        (lease.holder, lease.priority, lease.acquired_at, lease.expires_at),
        (user("bob"), 9, 10, 10 + TTL)
    );
}

fn preemption_forbidden_is_busy<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    registry
        .acquire(&claim(&doc("d1"), "alice", 1, TTL), 0, Preemption::Forbidden)
        .unwrap();
    let outcome = registry
        .acquire(&claim(&doc("d1"), "bob", 9, TTL), 10, Preemption::Forbidden)
        .unwrap();
    assert!(matches!(outcome, Acquisition::Busy { .. }));
    assert_eq!(registry.holder(&doc("d1"), 10).unwrap().unwrap().holder, user("alice"));
}

fn expired_lease_frees_the_resource<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    registry
        .acquire(&claim(&doc("d1"), "alice", 9, TTL), 0, Preemption::Forbidden)
        .unwrap();
    let outcome = registry
        .acquire(&claim(&doc("d1"), "bob", 1, TTL), TTL, Preemption::Forbidden)
        .unwrap();
    assert_eq!(outcome, Acquisition::Granted);
    assert_eq!(registry.holder(&doc("d1"), TTL).unwrap().unwrap().holder, user("bob"));
}

fn expiry_is_exact<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    registry
        .acquire(&claim(&doc("d1"), "alice", 1, TTL), 0, Preemption::Forbidden)
        .unwrap();
    assert!(registry.holder(&doc("d1"), TTL - 1).unwrap().is_some());
    assert!(registry.holder(&doc("d1"), TTL).unwrap().is_none());
}

fn renew_extends<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    registry
        .acquire(&claim(&doc("d1"), "alice", 7, TTL), 0, Preemption::Forbidden)
        .unwrap();
    let renewed = registry.renew(&doc("d1"), &user("alice"), 900, TTL).unwrap();
    assert_eq!(
        (renewed.expires_at, renewed.priority, renewed.acquired_at),
        (900 + TTL, 7, 0)
    );
    assert_eq!(registry.holder(&doc("d1"), TTL + 500).unwrap().unwrap(), renewed);
}

fn renew_refusals<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    registry
        .acquire(&claim(&doc("d1"), "alice", 1, TTL), 0, Preemption::Forbidden)
        .unwrap();
    assert!(matches!(
        registry.renew(&doc("d1"), &user("bob"), 10, TTL),
        Err(ExclusiveError::NotHolder { holder, .. }) if holder == user("alice")
    ));
    assert!(matches!(
        registry.renew(&doc("d1"), &user("alice"), 10, 0),
        Err(ExclusiveError::ZeroTtl)
    ));
    assert!(matches!(
        registry.renew(&doc("d1"), &user("alice"), TTL, TTL),
        Err(ExclusiveError::NotHeld(_))
    ));
    assert!(matches!(
        registry.renew(&doc("none"), &user("alice"), 10, TTL),
        Err(ExclusiveError::NotHeld(_))
    ));
    assert_eq!(registry.holder(&doc("d1"), 10).unwrap().unwrap().expires_at, TTL);
}

fn only_the_holder_releases<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    registry
        .acquire(&claim(&doc("d1"), "alice", 1, TTL), 0, Preemption::Forbidden)
        .unwrap();
    assert!(matches!(
        registry.release(&doc("d1"), &user("bob"), 5),
        Err(ExclusiveError::NotHolder { .. })
    ));
    let released = registry.release(&doc("d1"), &user("alice"), 5).unwrap();
    assert_eq!(released.holder, user("alice"));
    assert!(registry.holder(&doc("d1"), 5).unwrap().is_none());
    assert!(matches!(
        registry.release(&doc("d1"), &user("alice"), 5),
        Err(ExclusiveError::NotHeld(_))
    ));
    registry
        .acquire(&claim(&doc("d2"), "alice", 1, TTL), 0, Preemption::Forbidden)
        .unwrap();
    assert!(matches!(
        registry.release(&doc("d2"), &user("alice"), TTL),
        Err(ExclusiveError::NotHeld(_))
    ));
}

fn reacquire_replaces<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    let mine = claim(&doc("d1"), "alice", 1, TTL);
    registry.acquire(&mine, 0, Preemption::Forbidden).unwrap();
    let outcome = registry.acquire(&mine, 500, Preemption::Forbidden).unwrap();
    assert_eq!(outcome, Acquisition::Granted);
    let lease = registry.holder(&doc("d1"), 500).unwrap().unwrap();
    assert_eq!((lease.acquired_at, lease.expires_at), (500, 500 + TTL));
}

fn expire_in_order<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    for id in ["b", "a"] {
        registry
            .acquire(&claim(&doc(id), "alice", 1, 10), 0, Preemption::Forbidden)
            .unwrap();
    }
    registry
        .acquire(&claim(&doc("long"), "alice", 1, 100), 0, Preemption::Forbidden)
        .unwrap();
    assert!(registry.expire(9).unwrap().is_empty());
    let expired = registry.expire(50).unwrap();
    let ids: Vec<_> = expired.iter().map(|lease| lease.resource.id.as_str()).collect();
    assert_eq!(ids, ["a", "b"]);
    assert!(registry.expire(50).unwrap().is_empty());
    assert!(registry.holder(&doc("long"), 50).unwrap().is_some());
    assert_eq!(registry.store().leases().unwrap().len(), 1);
}

fn max_ttl<S: ExclusiveStore>(store: S) {
    let mut registry = ExclusiveRegistry::new(store).with_max_ttl(TTL);
    assert!(matches!(
        registry.acquire(&claim(&doc("d1"), "alice", 1, TTL + 1), 0, Preemption::Forbidden),
        Err(ExclusiveError::TtlTooLong(max)) if max == TTL
    ));
    registry
        .acquire(&claim(&doc("d1"), "alice", 1, TTL), 0, Preemption::Forbidden)
        .unwrap();
    assert!(matches!(
        registry.renew(&doc("d1"), &user("alice"), 1, u64::MAX),
        Err(ExclusiveError::TtlTooLong(_))
    ));
}

fn extreme_priorities<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    let low = i64::MAX - 1;
    registry
        .acquire(&claim(&doc("d1"), "alice", low, TTL), 0, Preemption::Forbidden)
        .unwrap();
    let busy = registry
        .acquire(&claim(&doc("d1"), "bob", low, TTL), 1, Preemption::Allowed)
        .unwrap();
    assert!(matches!(busy, Acquisition::Busy { .. }));
    let taken = registry
        .acquire(&claim(&doc("d1"), "bob", i64::MAX, TTL), 1, Preemption::Allowed)
        .unwrap();
    assert!(matches!(taken, Acquisition::Preempted { previous } if previous.priority == low));
    registry
        .acquire(&claim(&doc("d2"), "alice", i64::MIN, TTL), 0, Preemption::Forbidden)
        .unwrap();
    let min = registry
        .acquire(&claim(&doc("d2"), "bob", i64::MIN + 1, TTL), 1, Preemption::Allowed)
        .unwrap();
    assert!(matches!(min, Acquisition::Preempted { .. }));
}

fn identities_do_not_collide<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    let a = ObjectRef::new("a:b", "c");
    let b = ObjectRef::new("a", "b:c");
    registry
        .acquire(
            &Claim::new(a.clone(), user("alice"), Terms::new(1, TTL)),
            0,
            Preemption::Forbidden,
        )
        .unwrap();
    let outcome = registry
        .acquire(
            &Claim::new(b.clone(), user("bob"), Terms::new(1, TTL)),
            0,
            Preemption::Forbidden,
        )
        .unwrap();
    assert_eq!(outcome, Acquisition::Granted);
    assert_eq!(registry.holder(&a, 0).unwrap().unwrap().holder, user("alice"));
    assert_eq!(registry.holder(&b, 0).unwrap().unwrap().holder, user("bob"));
    let accented = ObjectRef::new("document", "ação ✓ 'quote' \"dq\"");
    registry
        .acquire(
            &Claim::new(accented.clone(), user("alice"), Terms::new(1, TTL)),
            0,
            Preemption::Forbidden,
        )
        .unwrap();
    assert!(registry.holder(&accented, 0).unwrap().is_some());
}

fn empty_store_reads_nothing<S: ExclusiveStore>(registry: &mut ExclusiveRegistry<S>) {
    assert_eq!(registry.store().get(&doc("d1")).unwrap(), None);
    assert!(registry.store().leases().unwrap().is_empty());
    assert!(registry.expire(u64::from(u32::MAX)).unwrap().is_empty());
    assert!(registry.holder(&doc("d1"), 0).unwrap().is_none());
}
