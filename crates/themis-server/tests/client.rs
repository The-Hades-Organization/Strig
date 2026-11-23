//! The client: fail-closed answers, the circuit breaker on an injected clock, batches, and a
//! round trip against the server in process.
#![cfg(feature = "client")]

mod support;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use support::*;
use themis::Subject;
use themis_server::client::{
    BreakerConfig, BreakerState, Client, ClientConfig, ClientDecision, Failure, HttpTransport, RawResponse, Transport,
    TransportError,
};
use themis_server::wire::CheckRequest;
use themis_server::{ErrorCode, ManualClock, ServerConfig, TIMEOUT_HEADER};
use tower::ServiceExt;

fn ask(user: &str, id: &str) -> CheckRequest {
    CheckRequest::new(Subject::user(user), "document.view", document(id))
}

/// Replays canned outcomes, then reports unreachable.
struct Scripted {
    outcomes: Mutex<VecDeque<Result<RawResponse, TransportError>>>,
    calls: Mutex<u32>,
}

impl Scripted {
    fn new(outcomes: Vec<Result<RawResponse, TransportError>>) -> Arc<Self> {
        Arc::new(Self {
            outcomes: Mutex::new(outcomes.into()),
            calls: Mutex::new(0),
        })
    }

    fn calls(&self) -> u32 {
        *self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl Transport for Scripted {
    async fn post(&self, _path: &str, _timeout: Duration, _body: Vec<u8>) -> Result<RawResponse, TransportError> {
        *self.calls.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        self.outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::unreachable("script is empty")))
    }
}

fn status(status: u16, body: &str) -> Result<RawResponse, TransportError> {
    Ok(RawResponse {
        status,
        body: body.as_bytes().to_vec(),
    })
}

const UNAVAILABLE: &str = r#"{"error":{"code":"source_unavailable","message":"x"}}"#;

fn allow_body() -> String {
    serde_json::json!({
        "decision": {
            "effect": "allow",
            "reason": {"kind": "grant", "grant_id": "g", "permission": "document.view", "rank": 0, "strategy": "s"},
        },
        "evaluated_at": NOW,
    })
    .to_string()
}

fn breaker(threshold: u32, open_secs: u64) -> ClientConfig {
    ClientConfig::default().with_breaker(
        BreakerConfig::default()
            .with_failure_threshold(threshold)
            .with_open_for(Duration::from_secs(open_secs)),
    )
}

/// The server in process, behind the `Transport` trait.
struct InProcess(Router);

#[async_trait]
impl Transport for InProcess {
    async fn post(&self, path: &str, timeout: Duration, body: Vec<u8>) -> Result<RawResponse, TransportError> {
        let request = Request::post(path)
            .header("content-type", "application/json")
            .header(TIMEOUT_HEADER, timeout.as_millis().to_string())
            .body(Body::from(body))
            .map_err(TransportError::unreachable)?;
        let response = self
            .0
            .clone()
            .oneshot(request)
            .await
            .map_err(TransportError::unreachable)?;
        let status = response.status().as_u16();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(TransportError::unreachable)?
            .to_bytes()
            .to_vec();
        Ok(RawResponse { status, body })
    }
}

#[tokio::test]
async fn a_503_becomes_a_deny_with_the_typed_reason() {
    let transport = Scripted::new(vec![status(503, UNAVAILABLE)]);
    let client = Client::new(transport, ClientConfig::default());
    let decision = client.check(&ask("alice", "d1")).await;
    assert!(!decision.is_allowed());
    assert_eq!(
        decision.failure(),
        Some(&Failure::Server {
            status: 503,
            code: Some(ErrorCode::SourceUnavailable)
        })
    );
}

#[tokio::test]
async fn an_unreachable_server_is_a_deny() {
    let client = Client::new(Scripted::new(vec![]), ClientConfig::default());
    let decision = client.check(&ask("alice", "d1")).await;
    assert_eq!(decision.failure(), Some(&Failure::Unreachable));
    assert!(!decision.is_allowed());
}

#[tokio::test]
async fn a_5xx_without_an_error_body_is_still_a_deny() {
    let client = Client::new(
        Scripted::new(vec![status(502, "<html>bad gateway</html>")]),
        ClientConfig::default(),
    );
    let decision = client.check(&ask("alice", "d1")).await;
    assert_eq!(
        decision.failure(),
        Some(&Failure::Server {
            status: 502,
            code: None
        })
    );
}

#[tokio::test]
async fn a_4xx_is_a_rejection_and_a_deny() {
    let body = r#"{"error":{"code":"invalid_request","message":"x"}}"#;
    let client = Client::new(Scripted::new(vec![status(400, body)]), ClientConfig::default());
    let decision = client.check(&ask("alice", "d1")).await;
    assert_eq!(
        decision.failure(),
        Some(&Failure::Rejected {
            status: 400,
            code: Some(ErrorCode::InvalidRequest)
        })
    );
}

#[tokio::test]
async fn a_200_that_is_not_an_answer_is_a_deny() {
    let client = Client::new(Scripted::new(vec![status(200, "{}")]), ClientConfig::default());
    let decision = client.check(&ask("alice", "d1")).await;
    assert_eq!(decision.failure(), Some(&Failure::InvalidResponse));
}

#[tokio::test(start_paused = true)]
async fn a_call_past_the_timeout_is_a_deny() {
    struct Hangs;
    #[async_trait]
    impl Transport for Hangs {
        async fn post(&self, _: &str, _: Duration, _: Vec<u8>) -> Result<RawResponse, TransportError> {
            tokio::time::sleep(Duration::from_secs(60)).await;
            status(200, "{}")
        }
    }
    let config = ClientConfig::default().with_timeout(Duration::from_millis(50));
    let client = Client::new(Arc::new(Hangs), config);
    assert_eq!(
        client.check(&ask("alice", "d1")).await.failure(),
        Some(&Failure::Timeout)
    );
}

#[tokio::test]
async fn the_breaker_opens_after_the_threshold_and_stops_calling() {
    let clock = ManualClock::new(0);
    let transport = Scripted::new(vec![status(503, UNAVAILABLE), status(503, UNAVAILABLE)]);
    let client = Client::with_clock(transport.clone(), breaker(2, 30), Arc::new(clock));
    client.check(&ask("alice", "d1")).await;
    assert_eq!(client.breaker_state(), BreakerState::Closed);
    client.check(&ask("alice", "d1")).await;
    assert_eq!(client.breaker_state(), BreakerState::Open);

    let decision = client.check(&ask("alice", "d1")).await;
    assert_eq!(decision.failure(), Some(&Failure::CircuitOpen));
    assert_eq!(transport.calls(), 2, "an open circuit makes no call");
}

#[tokio::test]
async fn the_breaker_lets_one_probe_through_and_closes_on_success() {
    let clock = ManualClock::new(0);
    let transport = Scripted::new(vec![status(503, UNAVAILABLE), status(200, &allow_body())]);
    let client = Client::with_clock(transport.clone(), breaker(1, 30), Arc::new(clock.clone()));
    client.check(&ask("alice", "d1")).await;
    assert_eq!(client.breaker_state(), BreakerState::Open);

    clock.advance(29_999);
    assert_eq!(client.breaker_state(), BreakerState::Open);
    let refused = client.check(&ask("alice", "d1")).await;
    assert_eq!(refused.failure(), Some(&Failure::CircuitOpen));
    clock.advance(1);

    let probe = client.check(&ask("alice", "d1")).await;
    assert!(probe.is_allowed());
    assert_eq!(client.breaker_state(), BreakerState::Closed);
}

#[tokio::test]
async fn a_failed_probe_reopens_the_circuit() {
    let clock = ManualClock::new(0);
    let transport = Scripted::new(vec![status(503, UNAVAILABLE), status(503, UNAVAILABLE)]);
    let client = Client::with_clock(transport, breaker(1, 10), Arc::new(clock.clone()));
    client.check(&ask("alice", "d1")).await;
    clock.advance(10_000);
    client.check(&ask("alice", "d1")).await;
    assert_eq!(client.breaker_state(), BreakerState::Open);
    let decision = client.check(&ask("alice", "d1")).await;
    assert_eq!(decision.failure(), Some(&Failure::CircuitOpen));
}

#[tokio::test]
async fn a_rejection_does_not_count_against_the_circuit() {
    let body = r#"{"error":{"code":"invalid_request","message":"x"}}"#;
    let transport = Scripted::new(vec![status(400, body), status(400, body)]);
    let client = Client::with_clock(transport, breaker(1, 30), Arc::new(ManualClock::new(0)));
    client.check(&ask("alice", "d1")).await;
    client.check(&ask("alice", "d1")).await;
    assert_eq!(client.breaker_state(), BreakerState::Closed);
}

#[tokio::test]
async fn the_client_matches_the_server_on_allow_and_deny() {
    let router = memory_server(ServerConfig::default());
    let client = Client::new(Arc::new(InProcess(router)), ClientConfig::default());
    let allowed = client.check(&ask("alice", "d1")).await;
    let denied = client.check(&ask("mallory", "d1")).await;
    assert!(allowed.is_allowed());
    assert!(matches!(denied, ClientDecision::Remote(_)));
    assert!(!denied.is_allowed());
}

#[tokio::test]
async fn a_batch_is_one_call_and_keeps_the_order() {
    let router = memory_server(ServerConfig::default());
    let client = Client::new(Arc::new(InProcess(router)), ClientConfig::default());
    let requests = [
        ask("alice", "1"),
        ask("mallory", "2"),
        ask("alice", "3"),
        ask("mallory", "4"),
    ];
    let answers = client.check_batch(&requests).await;
    let allowed: Vec<_> = answers.iter().map(ClientDecision::is_allowed).collect();
    assert_eq!(allowed, [true, false, true, false]);
}

#[tokio::test]
async fn a_failed_batch_denies_every_check_and_an_empty_one_makes_no_call() {
    let transport = Scripted::new(vec![status(503, UNAVAILABLE)]);
    let client = Client::new(transport.clone(), ClientConfig::default());
    assert!(client.check_batch(&[]).await.is_empty());
    assert_eq!(transport.calls(), 0);
    let answers = client.check_batch(&[ask("alice", "1"), ask("alice", "2")]).await;
    assert_eq!(answers.len(), 2);
    assert!(answers.iter().all(|a| !a.is_allowed() && a.failure().is_some()));
}

#[tokio::test]
async fn a_batch_with_a_wrong_count_is_denied() {
    let body = format!(r#"{{"results":[{}]}}"#, allow_body());
    let client = Client::new(Scripted::new(vec![status(200, &body)]), ClientConfig::default());
    let answers = client.check_batch(&[ask("alice", "1"), ask("alice", "2")]).await;
    assert!(answers.iter().all(|a| a.failure() == Some(&Failure::InvalidResponse)));
}

#[tokio::test]
async fn a_failing_source_behind_the_server_denies_through_the_client() {
    let router = server(Arc::new(FailingSource), ServerConfig::default());
    let client = Client::new(Arc::new(InProcess(router)), ClientConfig::default());
    let decision = client.check(&ask("alice", "d1")).await;
    assert!(!decision.is_allowed());
    assert_eq!(
        decision.failure(),
        Some(&Failure::Server {
            status: 503,
            code: Some(ErrorCode::SourceUnavailable)
        })
    );
}

#[tokio::test]
async fn list_failure_is_an_error_not_an_empty_listing() {
    let client = Client::new(Scripted::new(vec![status(503, UNAVAILABLE)]), ClientConfig::default());
    let request = themis_server::wire::ListRequest {
        subject: Subject::user("alice"),
        permission: "document.view".into(),
        kind: "document".into(),
        layout: None,
        resources: None,
        env: themis::Attributes::new(),
        at: None,
    };
    assert!(client.list(&request).await.is_err());
}

#[tokio::test]
async fn the_http_transport_round_trips_over_loopback() {
    let router = memory_server(ServerConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let serving = tokio::spawn(async move { axum::serve(listener, router).await });
    let transport = HttpTransport::new(format!("http://{addr}"));
    let client = Client::new(Arc::new(transport), ClientConfig::default());
    assert!(client.check(&ask("alice", "d1")).await.is_allowed());
    assert!(!client.check(&ask("mallory", "d1")).await.is_allowed());
    serving.abort();
    assert!(serving.await.expect_err("aborted").is_cancelled());
}
