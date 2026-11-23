//! The routes: answers, the stable error codes, and fail-closed behavior.

mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::*;
use themis::{Resource, Subject};
use themis_server::{BrokenClock, DecisionServer, MemorySource, ServerConfig, TIMEOUT_HEADER};

fn check_body(user: &str, id: &str) -> Value {
    json!({
        "subject": serde_json::to_value(Subject::user(user)).unwrap(),
        "permission": "document.view",
        "resource": serde_json::to_value(document(id)).unwrap(),
    })
}

#[tokio::test]
async fn check_allows_the_granted_user_and_stamps_the_server_clock() {
    let router = memory_server(ServerConfig::default());
    let mut body = check_body("alice", "d1");
    body["at"] = json!(42);
    let (status, answer) = send(&router, json_post("/v1/check", &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["decision"]["effect"], "allow");
    assert_eq!(answer["evaluated_at"], NOW);
    assert_eq!(answer["requested_at"], 42);
}

#[tokio::test]
async fn check_denies_a_user_without_a_grant() {
    let router = memory_server(ServerConfig::default());
    let (status, answer) = send(&router, json_post("/v1/check", &check_body("mallory", "d1"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["decision"]["effect"], "deny");
}

#[tokio::test]
async fn batch_answers_in_the_order_of_the_request() {
    let router = memory_server(ServerConfig::default());
    let body = json!({"checks": [
        check_body("alice", "d1"),
        check_body("mallory", "d2"),
        check_body("alice", "d3"),
    ]});
    let (status, answer) = send(&router, json_post("/v1/check/batch", &body)).await;
    assert_eq!(status, StatusCode::OK);
    let effects: Vec<_> = answer["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["decision"]["effect"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(effects, ["allow", "deny", "allow"]);
}

#[tokio::test]
async fn batch_over_the_limit_is_refused_with_a_stable_code() {
    let router = memory_server(ServerConfig::default().with_max_batch(2));
    let body = json!({"checks": [check_body("alice", "1"), check_body("alice", "2"), check_body("alice", "3")]});
    let (status, answer) = send(&router, json_post("/v1/check/batch", &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&answer), "batch_too_large");
}

#[tokio::test]
async fn batch_at_the_limit_and_empty_batch_are_answered() {
    let router = memory_server(ServerConfig::default().with_max_batch(1));
    let one = json!({"checks": [check_body("alice", "1")]});
    let (status, _) = send(&router, json_post("/v1/check/batch", &one)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, answer) = send(&router, json_post("/v1/check/batch", &json!({"checks": []}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["results"], json!([]));
}

#[tokio::test]
async fn malformed_json_is_a_stable_400() {
    let router = memory_server(ServerConfig::default());
    let (status, answer) = send(&router, raw_post("/v1/check", "application/json", "{not json".into())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&answer), "malformed_json");
}

#[tokio::test]
async fn json_that_does_not_fit_the_schema_is_invalid_request() {
    let router = memory_server(ServerConfig::default());
    let (status, answer) = send(&router, json_post("/v1/check", &json!({"permission": 3}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&answer), "invalid_request");
}

#[tokio::test]
async fn a_body_that_is_not_json_is_415() {
    let router = memory_server(ServerConfig::default());
    let (status, answer) = send(&router, raw_post("/v1/check", "text/plain", "hi".into())).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(error_code(&answer), "unsupported_media_type");
}

#[tokio::test]
async fn a_body_over_the_limit_is_413() {
    let router = memory_server(ServerConfig::default().with_max_body_bytes(64));
    let (status, answer) = send(&router, json_post("/v1/check", &check_body("alice", "d1"))).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error_code(&answer), "body_too_large");
}

#[tokio::test]
async fn unknown_route_and_wrong_method_have_stable_codes() {
    let router = memory_server(ServerConfig::default());
    let (status, answer) = send(&router, json_post("/v1/nope", &json!({}))).await;
    assert_eq!((status, error_code(&answer)), (StatusCode::NOT_FOUND, "not_found"));
    let get = axum::http::Request::get("/v1/check")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, answer) = send(&router, get).await;
    assert_eq!(
        (status, error_code(&answer)),
        (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
    );
}

#[tokio::test]
async fn a_failing_source_answers_503_and_never_allows() {
    let router = server(Arc::new(FailingSource), ServerConfig::default());
    let (status, answer) = send(&router, json_post("/v1/check", &check_body("alice", "d1"))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "source_unavailable");
    assert!(answer.get("decision").is_none());
    // the message is generic: the cause stays in the server log
    assert!(!answer["error"]["message"].as_str().unwrap().contains("store is down"));
}

#[tokio::test]
async fn every_route_fails_closed_with_a_failing_source() {
    let router = server(Arc::new(FailingSource), ServerConfig::default());
    let subject = serde_json::to_value(Subject::user("alice")).unwrap();
    let cases = [
        ("/v1/check/batch", json!({"checks": [check_body("alice", "d1")]})),
        (
            "/v1/list",
            json!({"subject": subject, "permission": "document.view", "kind": "document"}),
        ),
        ("/v1/who", json!({"permission": "document.view"})),
        (
            "/v1/access",
            json!({"resource": serde_json::to_value(document("d1")).unwrap()}),
        ),
    ];
    for (path, body) in cases {
        let (status, answer) = send(&router, json_post(path, &body)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(error_code(&answer), "source_unavailable", "{path}");
    }
}

#[tokio::test]
async fn a_broken_clock_answers_503() {
    let router = DecisionServer::new(Arc::new(MemorySource::new(snapshot())))
        .with_clock(Arc::new(BrokenClock))
        .router();
    let (status, answer) = send(&router, json_post("/v1/check", &check_body("alice", "d1"))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "clock_unavailable");
}

#[tokio::test(start_paused = true)]
async fn a_slow_source_past_the_deadline_answers_503() {
    let source = SlowSource {
        delay: Duration::from_secs(5),
        inner: MemorySource::new(snapshot()),
    };
    let router = server(
        Arc::new(source),
        ServerConfig::default().with_default_timeout(Duration::from_millis(100)),
    );
    let (status, answer) = send(&router, json_post("/v1/check", &check_body("alice", "d1"))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "deadline_exceeded");
}

#[tokio::test(start_paused = true)]
async fn the_deadline_header_is_capped_by_the_server_ceiling() {
    let source = SlowSource {
        delay: Duration::from_secs(5),
        inner: MemorySource::new(snapshot()),
    };
    let config = ServerConfig::default().with_max_timeout(Duration::from_millis(200));
    let router = server(Arc::new(source), config);
    let mut request = json_post("/v1/check", &check_body("alice", "d1"));
    request.headers_mut().insert(TIMEOUT_HEADER, "3600000".parse().unwrap());
    let (status, answer) = send(&router, request).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "deadline_exceeded");
}

#[tokio::test]
async fn a_bad_deadline_header_is_invalid_request() {
    let router = memory_server(ServerConfig::default());
    for value in ["0", "abc", "-5"] {
        let mut request = json_post("/v1/check", &check_body("alice", "d1"));
        request.headers_mut().insert(TIMEOUT_HEADER, value.parse().unwrap());
        let (status, answer) = send(&router, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
        assert_eq!(error_code(&answer), "invalid_request", "{value}");
    }
}

#[tokio::test]
async fn list_returns_the_filter_and_settles_candidate_ids() {
    let router = memory_server(ServerConfig::default());
    let body = json!({
        "subject": serde_json::to_value(Subject::user("alice")).unwrap(),
        "permission": "document.view",
        "kind": "document",
        "resources": [serde_json::to_value(document("d1")).unwrap(), serde_json::to_value(document("d2")).unwrap()],
    });
    let (status, answer) = send(&router, json_post("/v1/list", &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["kind"], "document");
    assert_eq!(answer["ids"], json!(["d1", "d2"]));
}

#[tokio::test]
async fn list_with_too_many_candidates_is_refused() {
    let router = memory_server(ServerConfig::default().with_max_resources(1));
    let resources: Vec<Resource> = vec![document("d1"), document("d2")];
    let body = json!({
        "subject": serde_json::to_value(Subject::user("alice")).unwrap(),
        "permission": "document.view",
        "kind": "document",
        "resources": serde_json::to_value(resources).unwrap(),
    });
    let (status, answer) = send(&router, json_post("/v1/list", &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&answer), "too_many_resources");
}

#[tokio::test]
async fn who_names_the_user_with_the_grant() {
    let router = memory_server(ServerConfig::default());
    let (status, answer) = send(&router, json_post("/v1/who", &json!({"permission": "document.view"}))).await;
    assert_eq!(status, StatusCode::OK);
    let text = answer["entries"].to_string();
    assert!(text.contains("alice"), "{text}");
}

#[tokio::test]
async fn health_live_is_up_and_ready_follows_the_source() {
    let up = memory_server(ServerConfig::default());
    let get = |p: &str| {
        axum::http::Request::get(p.to_owned())
            .body(axum::body::Body::empty())
            .unwrap()
    };
    assert_eq!(send(&up, get("/health/live")).await.0, StatusCode::OK);
    assert_eq!(send(&up, get("/health/ready")).await.0, StatusCode::OK);

    let down = server(Arc::new(FailingSource), ServerConfig::default());
    assert_eq!(send(&down, get("/health/live")).await.0, StatusCode::OK);
    let (status, answer) = send(&down, get("/health/ready")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "source_unavailable");
}

#[tokio::test]
async fn a_query_over_the_limits_answers_503_instead_of_a_partial_list() {
    let limits = themis::QueryLimits::default().with_max_parties(0);
    let router = memory_server(ServerConfig::default().with_query_limits(limits));
    let (status, answer) = send(
        &router,
        json_post(
            "/v1/who",
            &json!({"permission": "document.view", "resource": serde_json::to_value(document("d1")).unwrap()}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&answer), "query_limit_exceeded");
    assert!(answer.get("entries").is_none());
}
