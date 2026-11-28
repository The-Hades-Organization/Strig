//! Metrics of the hub, the relay and the sessions, and that their labels carry nothing identifying.
//!
//! One test in its own process: the recorder is global because the relay and the sessions run on
//! spawned tasks. A snapshot of the debugging recorder drains its counters, so the test takes one.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use strig::{Anchor, Resource, Subject};
use strig_sync::{Change, ChangeStream, Hub, MemoryTransport, Session, SessionOptions, Transport, TransportError};

const SECRET_SUBJECT: &str = "u-secret-4417";
const SECRET_SCOPE: &str = "scope-secret-9921";

struct Broken;

#[async_trait]
impl Transport for Broken {
    fn name(&self) -> &str {
        "broken"
    }

    async fn publish(&self, _change: &Change) -> Result<(), TransportError> {
        Err(TransportError::Closed)
    }

    async fn subscribe(&self) -> Result<ChangeStream, TransportError> {
        Err(TransportError::Closed)
    }
}

type Samples = BTreeMap<String, Vec<(BTreeMap<String, String>, f64)>>;

fn samples_of(snapshotter: &Snapshotter) -> Samples {
    let mut samples = Samples::new();
    for (composite, _, _, value) in snapshotter.snapshot().into_vec() {
        let key = composite.key();
        let labels = key
            .labels()
            .map(|label| (label.key().to_string(), label.value().to_string()))
            .collect();
        let number = match value {
            DebugValue::Counter(count) => count as f64,
            DebugValue::Gauge(gauge) => gauge.into_inner(),
            DebugValue::Histogram(values) => values.len() as f64,
        };
        samples
            .entry(key.name().to_string())
            .or_default()
            .push((labels, number));
    }
    samples
}

fn count(samples: &Samples, name: &str, wanted: &[(&str, &str)]) -> f64 {
    samples
        .get(name)
        .into_iter()
        .flatten()
        .filter(|(labels, _)| {
            wanted
                .iter()
                .all(|(k, v)| labels.get(*k).map(String::as_str) == Some(*v))
        })
        .map(|(_, value)| *value)
        .sum()
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[tokio::test]
async fn hub_relay_and_sessions_report_without_identifying_data() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("the only recorder of this process");

    let hub = Hub::builder().origin("a").transport(MemoryTransport::new(64)).build();
    let relay = hub.spawn_relay();
    let (_control, stream) = Session::open(
        &hub,
        Subject::user(SECRET_SUBJECT),
        vec![Resource::new("project", SECRET_SCOPE)],
        None,
        SessionOptions::default(),
    );
    settle().await;

    hub.publish(Change::grants(Anchor::new("org", SECRET_SCOPE)).for_subject(SECRET_SUBJECT))
        .await
        .expect("published");
    settle().await;
    drop(stream);
    settle().await;
    drop(relay);

    let broken = Hub::builder().origin("b").transport(Broken).build();
    broken.publish(Change::grants(Anchor::global())).await.unwrap_err();
    let _relay = broken.spawn_relay();
    settle().await;
    let samples = samples_of(&snapshotter);
    assert_eq!(
        count(
            &samples,
            "strig_sync_changes_total",
            &[("kind", "grants"), ("direction", "published")]
        ),
        2.0,
        "the broken transport still stamps and delivers locally"
    );
    assert_eq!(count(&samples, "strig_sync_sessions_opened_total", &[]), 1.0);
    assert_eq!(
        count(&samples, "strig_sync_sessions_open", &[]),
        0.0,
        "opened and closed balance out"
    );
    assert_eq!(
        count(&samples, "strig_sync_publish_errors_total", &[("transport", "broken")]),
        1.0
    );
    assert!(
        count(
            &samples,
            "strig_sync_transport_failures_total",
            &[("stage", "subscribe")]
        ) >= 1.0
    );

    for (name, entries) in &samples {
        for (labels, _) in entries {
            for (key, value) in labels {
                assert!(
                    ["kind", "direction", "transport", "stage", "reason"].contains(&key.as_str()),
                    "{name}: unexpected label {key}"
                );
                assert!(
                    !value.contains(SECRET_SUBJECT) && !value.contains(SECRET_SCOPE),
                    "{name}: label {key}={value} carries an identifier"
                );
            }
        }
    }
}
