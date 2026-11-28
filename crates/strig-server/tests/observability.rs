//! Metrics of the server and the client, and that their labels carry nothing identifying.

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::http::StatusCode;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use serde_json::json;
use strig::Subject;
use strig_server::client::{BreakerConfig, Client, ClientConfig, Failure, RawResponse, Transport, TransportError};
use strig_server::wire::CheckRequest;
use strig_server::{ManualClock, ServerConfig};
use support::*;

const SECRET_USER: &str = "u-secret-4417";
const SECRET_DOC: &str = "doc-secret-9921";

type Samples = BTreeMap<String, Vec<(BTreeMap<String, String>, f64)>>;

struct Down;

#[async_trait]
impl Transport for Down {
    async fn post(&self, _path: &str, _timeout: Duration, _body: Vec<u8>) -> Result<RawResponse, TransportError> {
        Ok(RawResponse {
            status: 503,
            body: br#"{"error":{"code":"source_unavailable","message":"down"}}"#.to_vec(),
        })
    }
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

#[tokio::test(flavor = "current_thread")]
async fn server_and_client_report_without_identifying_data() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);

    let router = memory_server(ServerConfig::default());
    let body = json!({
        "subject": serde_json::to_value(Subject::user(SECRET_USER)).unwrap(),
        "permission": "document.view",
        "resource": serde_json::to_value(document(SECRET_DOC)).unwrap(),
    });
    let (status, _) = send(&router, json_post("/v1/check", &body)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&router, raw_post("/v1/check", "application/json", "{".into())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let config = ClientConfig::default().with_breaker(
        BreakerConfig::default()
            .with_failure_threshold(1)
            .with_open_for(Duration::from_secs(30)),
    );
    let client = Client::with_clock(Arc::new(Down), config, Arc::new(ManualClock::new(0)));
    let request = CheckRequest::new(Subject::user(SECRET_USER), "document.view", document(SECRET_DOC));
    let first = client.check(&request).await;
    assert!(matches!(first.failure(), Some(Failure::Server { .. })));
    let second = client.check(&request).await;
    assert_eq!(second.failure(), Some(&Failure::CircuitOpen));

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

    assert_eq!(
        count(
            &samples,
            "strig_server_requests_total",
            &[("route", "/v1/check"), ("status", "200")]
        ),
        1.0
    );
    assert_eq!(
        count(&samples, "strig_server_requests_total", &[("status", "400")]),
        1.0
    );
    assert_eq!(
        count(&samples, "strig_server_errors_total", &[("code", "malformed_json")]),
        1.0
    );
    assert_eq!(
        count(
            &samples,
            "strig_server_request_duration_seconds",
            &[("route", "/v1/check")]
        ),
        2.0
    );
    assert_eq!(
        count(&samples, "strig_client_calls_total", &[("outcome", "server_error")]),
        1.0
    );
    assert_eq!(
        count(&samples, "strig_client_calls_total", &[("outcome", "circuit_open")]),
        1.0
    );
    assert_eq!(
        count(&samples, "strig_client_breaker_transitions_total", &[("to", "open")]),
        1.0
    );
    assert_eq!(count(&samples, "strig_client_breaker_state", &[]), 2.0);

    let allowed = ["route", "status", "code", "outcome", "to"];
    for (name, entries) in &samples {
        for (labels, _) in entries {
            for (key, value) in labels {
                assert!(allowed.contains(&key.as_str()), "{name}: unexpected label {key}");
                assert!(
                    !value.contains(SECRET_USER) && !value.contains(SECRET_DOC),
                    "{name}: label {key}={value} carries an identifier"
                );
            }
        }
    }
}
