//! Servidor de demonstração: SSE, WebSocket, a spec do motor para o frontend e uma rota que
//! concede permissão e avisa os clientes conectados.
//!
//! `cargo run -p themis-axum --example server` (porta em `PORT`, padrão 3000; a escolhida é
//! impressa na saída). O usuário vem do cabeçalho `x-user` (padrão `alice`).

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use axum::extract::{Path, RawQuery, State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use themis::{Anchor, EngineSpec, Grant, Resource, Subject, SubjectMatcher, TargetSelector};
use themis_axum::Realtime;
use themis_sync::{BoxError, Change, EngineProvider, GrantLoader, Hub, scope_from_str};

const SPEC: &str = r#"{
  "catalog": {
    "targetKinds": ["project", "document"],
    "broadTargets": ["org"],
    "permissions": [
      {"key": "project.view", "targets": ["project"]},
      {"key": "project.edit", "targets": ["project"]},
      {"key": "document.view", "targets": ["project", "document"], "impliedBy": ["project.view"]}
    ]
  }
}"#;

#[derive(Clone)]
struct App {
    realtime: Realtime,
    grants: Arc<RwLock<Vec<Grant>>>,
}

struct Store(Arc<RwLock<Vec<Grant>>>);

#[async_trait]
impl GrantLoader for Store {
    async fn load(&self, _: &Subject, _: &Resource) -> Result<Vec<Grant>, BoxError> {
        Ok(self.0.read().unwrap().clone())
    }
}

fn subject(headers: &HeaderMap) -> Subject {
    Subject::user(headers.get("x-user").and_then(|v| v.to_str().ok()).unwrap_or("alice"))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                        continue;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn scopes(query: Option<String>) -> Vec<Resource> {
    query
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.strip_prefix("scope="))
        .map(|value| scope_from_str(&percent_decode(value)))
        .collect()
}

async fn events(State(app): State<App>, headers: HeaderMap, RawQuery(query): RawQuery) -> impl IntoResponse {
    app.realtime.sse(subject(&headers), scopes(query))
}

async fn socket(
    State(app): State<App>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    app.realtime.websocket(upgrade, subject(&headers), scopes(query))
}

async fn engine_spec() -> impl IntoResponse {
    Json(serde_json::from_str::<serde_json::Value>(SPEC).unwrap())
}

/// Concede `permission` a `user` em `project:<id>` e avisa os clientes.
async fn grant(
    State(app): State<App>,
    Path((project, user, permission)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let id = format!("{user}:{permission}:{project}");
    app.grants.write().unwrap().push(Grant::allow(
        id.clone(),
        SubjectMatcher::user(user),
        permission,
        TargetSelector::exact("project", project.clone()),
    ));
    let change = Change::grants(Anchor::new("project", project)).with_id(id);
    match app.realtime.hub().publish(change).await {
        Ok(sent) => Json(serde_json::to_value(sent).unwrap()).into_response(),
        Err(error) => (axum::http::StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let spec: EngineSpec = serde_json::from_str(SPEC)?;
    let engine = Arc::new(spec.build()?);
    let grants = Arc::new(RwLock::new(Vec::new()));
    let hub = Hub::new();
    let provider = EngineProvider::new(engine, Store(grants.clone()));
    let app = App {
        realtime: Realtime::new(hub).with_provider(Arc::new(provider)),
        grants,
    };
    let router = Router::new()
        .route("/spec", get(engine_spec))
        .route("/events", get(events))
        .route("/ws", get(socket))
        .route("/grant/{project}/{user}/{permission}", post(grant))
        .with_state(app);
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router).await?;
    Ok(())
}
