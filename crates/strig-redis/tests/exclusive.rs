//! Precisa de um Redis em `STRIG_REDIS_URL`; sem a variável cada teste é pulado. Cada teste usa um
//! prefixo próprio.
#![cfg(feature = "exclusive")]

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use strig::ObjectRef;
use strig::exclusive::{Acquisition, Claim, ExclusiveRegistry, ExclusiveStore, Preemption, Terms};
use strig::exclusive_conformance;
use strig_redis::RedisExclusiveStore;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn url() -> Option<String> {
    let url = std::env::var("STRIG_REDIS_URL").ok();
    if url.is_none() {
        eprintln!("STRIG_REDIS_URL ausente: teste pulado");
    }
    url
}

fn prefix() -> String {
    format!(
        "strig:test:x{}:{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn doc(id: &str) -> ObjectRef {
    ObjectRef::new("document", id)
}

fn user(id: &str) -> ObjectRef {
    ObjectRef::new("user", id)
}

#[test]
fn passes_the_same_battery_as_the_memory_store() {
    let Some(url) = url() else { return };
    exclusive_conformance::run(|| RedisExclusiveStore::new(&url, prefix()).unwrap());
}

#[test]
fn two_instances_racing_for_one_resource_have_exactly_one_winner() {
    let Some(url) = url() else { return };
    let prefix = prefix();
    for round in 0..20 {
        let resource = doc(&format!("race{round}"));
        let handles: Vec<_> = (0..4)
            .map(|contender| {
                let mut registry = ExclusiveRegistry::new(RedisExclusiveStore::new(&url, prefix.clone()).unwrap());
                let resource = resource.clone();
                std::thread::spawn(move || {
                    let claim = Claim::new(resource, user(&format!("u{contender}")), Terms::new(1, 60_000));
                    registry.acquire(&claim, 0, Preemption::Forbidden).unwrap()
                })
            })
            .collect();
        let outcomes: Vec<Acquisition> = handles.into_iter().map(|handle| handle.join().unwrap()).collect();
        let granted = outcomes
            .iter()
            .filter(|outcome| **outcome == Acquisition::Granted)
            .count();
        assert_eq!(granted, 1, "round {round}");
    }
}

#[test]
fn racing_preemptions_leave_the_highest_priority() {
    let Some(url) = url() else { return };
    let prefix = prefix();
    let resource = doc("pre");
    let handles: Vec<_> = (1..=6_i64)
        .map(|priority| {
            let mut registry = ExclusiveRegistry::new(RedisExclusiveStore::new(&url, prefix.clone()).unwrap());
            let resource = resource.clone();
            std::thread::spawn(move || {
                let claim = Claim::new(resource, user(&format!("u{priority}")), Terms::new(priority, 60_000));
                registry.acquire(&claim, 0, Preemption::Allowed).unwrap();
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let registry = ExclusiveRegistry::new(RedisExclusiveStore::new(&url, prefix).unwrap());
    let lease = registry.holder(&resource, 1).unwrap().unwrap();
    assert_eq!((lease.priority, lease.holder), (6, user("u6")));
}

#[test]
fn expire_does_not_remove_a_lease_taken_after_it_ran_out() {
    let Some(url) = url() else { return };
    let prefix = prefix();
    let mut a = ExclusiveRegistry::new(RedisExclusiveStore::new(&url, prefix.clone()).unwrap());
    let mut b = ExclusiveRegistry::new(RedisExclusiveStore::new(&url, prefix).unwrap());
    let resource = doc("sweep");
    a.acquire(
        &Claim::new(resource.clone(), user("alice"), Terms::new(1, 10)),
        0,
        Preemption::Forbidden,
    )
    .unwrap();
    b.acquire(
        &Claim::new(resource.clone(), user("bob"), Terms::new(1, 1_000)),
        20,
        Preemption::Forbidden,
    )
    .unwrap();
    assert!(a.expire(20).unwrap().is_empty());
    assert_eq!(a.holder(&resource, 20).unwrap().unwrap().holder, user("bob"));
}

#[test]
fn the_caller_clock_decides_and_redis_only_reclaims_after_the_retention() {
    let Some(url) = url() else { return };
    let store = RedisExclusiveStore::new(&url, prefix())
        .unwrap()
        .with_retention(Duration::from_millis(300));
    let mut registry = ExclusiveRegistry::new(store);
    let resource = doc("clock");
    registry
        .acquire(
            &Claim::new(resource.clone(), user("alice"), Terms::new(1, 50)),
            1_000_000,
            Preemption::Forbidden,
        )
        .unwrap();
    // Real time barely moved, but the caller's clock says the lease ran out.
    assert!(registry.holder(&resource, 1_000_050).unwrap().is_none());
    assert_eq!(registry.store().leases().unwrap().len(), 1);
    std::thread::sleep(Duration::from_millis(600));
    assert!(registry.store().get(&resource).unwrap().is_none());
    assert!(registry.expire(2_000_000).unwrap().is_empty());
}

#[test]
fn a_store_that_cannot_connect_fails_closed() {
    let mut store = RedisExclusiveStore::new("redis://127.0.0.1:1/", prefix())
        .unwrap()
        .with_timeout(Duration::from_millis(200));
    let claim = Claim::new(doc("x"), user("alice"), Terms::new(1, 1_000));
    assert!(store.acquire_lease(&claim, 0, Preemption::Forbidden).is_err());
    assert!(store.get(&doc("x")).is_err());
}

#[test]
fn a_corrupt_value_is_an_error_not_a_free_resource() {
    let Some(url) = url() else { return };
    let prefix = prefix();
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut raw = client.get_connection().unwrap();
    let key = format!("{{{prefix}}}:lease:8:document:bad");
    redis::cmd("SET")
        .arg(&key)
        .arg("not json")
        .query::<()>(&mut raw)
        .unwrap();
    let mut store = RedisExclusiveStore::new(&url, prefix).unwrap();
    let claim = Claim::new(doc("bad"), user("alice"), Terms::new(1, 1_000));
    assert!(store.acquire_lease(&claim, 0, Preemption::Forbidden).is_err());
    assert!(store.get(&doc("bad")).is_err());
    redis::cmd("DEL").arg(&key).query::<()>(&mut raw).unwrap();
}

#[test]
fn a_prefix_with_braces_or_empty_is_refused() {
    assert!(RedisExclusiveStore::new("redis://127.0.0.1/", "").is_err());
    assert!(RedisExclusiveStore::new("redis://127.0.0.1/", "a{b").is_err());
}
