//! Precisa de um Redis em `STRIG_REDIS_URL` (ex.: `redis://127.0.0.1:6379/`); sem a
//! variável o teste não roda nada.

use std::time::Duration;

use strig::Anchor;
use strig_redis::RedisTransport;
use strig_sync::{Change, ChangeKind, Hub};

#[tokio::test]
async fn two_hubs_exchange_changes_over_redis() {
    let Ok(url) = std::env::var("STRIG_REDIS_URL") else {
        eprintln!("STRIG_REDIS_URL ausente: teste pulado");
        return;
    };
    let channel = format!("strig:test:{}", std::process::id());
    let a = Hub::builder()
        .origin("a")
        .transport(RedisTransport::new(&url, channel.clone()).unwrap())
        .build();
    let b = Hub::builder()
        .origin("b")
        .transport(RedisTransport::new(&url, channel).unwrap())
        .build();
    let _ra = a.spawn_relay();
    let _rb = b.spawn_relay();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut at_b = b.subscribe();
    a.publish(Change::grants(Anchor::new("org", "o1")).with_id("g1"))
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), at_b.recv())
        .await
        .expect("mudança chega pelo Redis")
        .unwrap();
    assert_eq!(got.kind, ChangeKind::Grants);
    assert_eq!(got.origin, "a");
    assert_eq!(got.id.as_deref(), Some("g1"));
}
