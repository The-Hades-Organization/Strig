//! Needs a Postgres in `STRIG_PG_URL`; without the variable every test skips. Each test works in a
//! schema of its own.
#![cfg(feature = "exclusive")]

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use strig::ObjectRef;
use strig::exclusive::{Acquisition, Claim, ExclusiveRegistry, ExclusiveStore, Preemption, Terms};
use strig::exclusive_conformance;
use strig_postgres::{PgExclusiveStore, PgTables, connect, migrate_with};
use tokio_postgres::Client;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Db {
    url: String,
    tables: PgTables,
    client: Client,
    schema: String,
}

impl Db {
    async fn new() -> Option<Self> {
        let Ok(url) = std::env::var("STRIG_PG_URL") else {
            eprintln!("STRIG_PG_URL absent: test skipped");
            return None;
        };
        let schema = format!(
            "strig_x{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tables = PgTables::default().in_schema(&schema).unwrap();
        let client = connect(&url).await.unwrap();
        migrate_with(&client, &tables).await.unwrap();
        Some(Self {
            url,
            tables,
            client,
            schema,
        })
    }

    async fn store(&self) -> PgExclusiveStore {
        PgExclusiveStore::connect(&self.url, self.tables.clone()).await.unwrap()
    }

    async fn drop_schema(self) {
        self.client
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .await
            .unwrap();
    }
}

fn table_of(db: &Db) -> String {
    format!("\"{}\".\"strig_exclusive\"", db.schema)
}

fn doc(id: &str) -> ObjectRef {
    ObjectRef::new("document", id)
}

fn user(id: &str) -> ObjectRef {
    ObjectRef::new("user", id)
}

#[tokio::test(flavor = "multi_thread")]
async fn passes_the_same_battery_as_the_memory_store() {
    let Some(db) = Db::new().await else { return };
    let mut stores = Vec::new();
    for _ in 0..16 {
        stores.push(db.store().await);
    }
    let url = db.url.clone();
    let client = connect(&url).await.unwrap();
    let truncate = format!("TRUNCATE {}", table_of(&db));
    tokio::task::spawn_blocking(move || {
        let handle = tokio::runtime::Handle::current();
        let mut stores = stores.into_iter();
        exclusive_conformance::run(|| {
            handle.block_on(client.batch_execute(&truncate)).unwrap();
            stores.next().unwrap()
        });
    })
    .await
    .unwrap();
    db.drop_schema().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_instances_racing_for_one_resource_have_exactly_one_winner() {
    let Some(db) = Db::new().await else { return };
    for round in 0..20 {
        let resource = doc(&format!("race{round}"));
        let mut handles = Vec::new();
        for contender in 0..4 {
            let mut registry = ExclusiveRegistry::new(db.store().await);
            let resource = resource.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                let claim = Claim::new(resource, user(&format!("u{contender}")), Terms::new(1, 60_000));
                registry.acquire(&claim, 0, Preemption::Forbidden).unwrap()
            }));
        }
        let mut granted = 0;
        for handle in handles {
            if handle.await.unwrap() == Acquisition::Granted {
                granted += 1;
            }
        }
        assert_eq!(granted, 1, "round {round}");
    }
    db.drop_schema().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn racing_preemptions_leave_the_highest_priority() {
    let Some(db) = Db::new().await else { return };
    let resource = doc("pre");
    let mut handles = Vec::new();
    for priority in 1..=6_i64 {
        let mut registry = ExclusiveRegistry::new(db.store().await);
        let resource = resource.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            let claim = Claim::new(resource, user(&format!("u{priority}")), Terms::new(priority, 60_000));
            registry.acquire(&claim, 0, Preemption::Allowed).unwrap();
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    let registry = ExclusiveRegistry::new(db.store().await);
    let lease = tokio::task::spawn_blocking(move || registry.holder(&resource, 1).unwrap().unwrap())
        .await
        .unwrap();
    assert_eq!((lease.priority, lease.holder), (6, user("u6")));
    db.drop_schema().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_expire_and_reacquire_never_removes_a_live_lease() {
    let Some(db) = Db::new().await else { return };
    let mut a = ExclusiveRegistry::new(db.store().await);
    let mut b = ExclusiveRegistry::new(db.store().await);
    let resource = doc("sweep");
    tokio::task::spawn_blocking(move || {
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
    })
    .await
    .unwrap();
    db.drop_schema().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_store_that_cannot_answer_fails_closed() {
    let Some(db) = Db::new().await else { return };
    let mut store = db.store().await.with_timeout(Duration::from_millis(1));
    let lock = db
        .client
        .batch_execute(&format!("BEGIN; LOCK TABLE {} IN ACCESS EXCLUSIVE MODE", table_of(&db)))
        .await;
    lock.unwrap();
    let outcome = tokio::task::spawn_blocking(move || {
        store.acquire_lease(
            &Claim::new(doc("blocked"), user("alice"), Terms::new(1, 1_000)),
            0,
            Preemption::Forbidden,
        )
    })
    .await
    .unwrap();
    assert!(outcome.is_err());
    db.client.batch_execute("ROLLBACK").await.unwrap();
    db.drop_schema().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_instant_beyond_bigint_is_an_error_not_a_wrap() {
    let Some(db) = Db::new().await else { return };
    let mut registry = ExclusiveRegistry::new(db.store().await);
    let outcome = tokio::task::spawn_blocking(move || {
        registry.acquire(
            &Claim::new(doc("far"), user("alice"), Terms::new(1, u64::MAX)),
            u64::MAX - 1,
            Preemption::Forbidden,
        )
    })
    .await
    .unwrap();
    assert!(outcome.is_err());
    db.drop_schema().await;
}
