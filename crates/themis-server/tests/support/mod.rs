#![allow(dead_code)] // each test binary uses a part of this module

//! A tiny catalog, engine and grants, plus sources that fail or stall.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;
use themis::{Catalog, Engine, Grant, PermissionDef, Resource, SubjectMatcher, TargetSelector};
use themis_server::{DecisionServer, DecisionSource, ManualClock, MemorySource, ServerConfig, Snapshot, SourceError};
use tower::ServiceExt;

pub const NOW: u64 = 1_700_000_000_000;

pub fn engine() -> Arc<Engine> {
    let catalog = Catalog::builder()
        .target_kinds(["document"])
        .broad_target("org")
        .permission(PermissionDef::new("document.view").targets(["document"]))
        .build()
        .expect("catalog");
    Arc::new(Engine::builder(catalog).build().expect("engine"))
}

/// `alice` may view every document; nobody else holds anything.
pub fn grants() -> Vec<Grant> {
    vec![Grant::allow(
        "alice-view",
        SubjectMatcher::user("alice"),
        "document.view",
        TargetSelector::kind("document"),
    )]
}

pub fn snapshot() -> Snapshot {
    Snapshot::new(engine(), grants())
}

pub fn document(id: &str) -> Resource {
    Resource::new("document", id).within("org", "o1")
}

pub fn server(source: Arc<dyn DecisionSource>, config: ServerConfig) -> Router {
    DecisionServer::new(source)
        .with_clock(Arc::new(ManualClock::new(NOW)))
        .with_config(config)
        .router()
}

pub fn memory_server(config: ServerConfig) -> Router {
    server(Arc::new(MemorySource::new(snapshot())), config)
}

/// A source whose store is down.
pub struct FailingSource;

#[async_trait]
impl DecisionSource for FailingSource {
    async fn snapshot(&self) -> Result<Arc<Snapshot>, SourceError> {
        Err(SourceError::unavailable("the store is down"))
    }
}

/// A source that answers only after `delay`, on the (paused) tokio clock.
pub struct SlowSource {
    pub delay: Duration,
    pub inner: MemorySource,
}

#[async_trait]
impl DecisionSource for SlowSource {
    async fn snapshot(&self) -> Result<Arc<Snapshot>, SourceError> {
        tokio::time::sleep(self.delay).await;
        self.inner.snapshot().await
    }
}

pub fn json_post(path: &str, body: &Value) -> Request<Body> {
    raw_post(path, "application/json", body.to_string())
}

pub fn raw_post(path: &str, content_type: &str, body: String) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .expect("request")
}

pub async fn send(router: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.clone().oneshot(request).await.expect("infallible");
    let status = response.status();
    let bytes = response.into_body().collect().await.expect("body").to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

pub fn error_code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or("<none>")
}
