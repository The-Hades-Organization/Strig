use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use themis::{Anchor, Catalog, Engine, Grant, PermissionDef, Subject, SubjectMatcher, TargetSelector};
use themis_axum::Realtime;
use themis_sync::{Change, EngineProvider, Hub, ServerMessage, scope_from_str};
use tower::ServiceExt;

#[derive(serde::Deserialize)]
struct Params {
    scope: String,
}

async fn sse(State(rt): State<Realtime>, Query(p): Query<Params>) -> impl IntoResponse {
    rt.sse(Subject::user("alice"), vec![scope_from_str(&p.scope)])
}

async fn ws(State(rt): State<Realtime>, upgrade: WebSocketUpgrade) -> impl IntoResponse {
    rt.websocket(upgrade, Subject::user("alice"), Vec::new())
}

fn app(hub: Hub) -> Router {
    let catalog = Catalog::builder()
        .target_kinds(["project"])
        .broad_target("org")
        .permission(PermissionDef::new("project.view").targets(["project"]))
        .build()
        .unwrap();
    let engine = Arc::new(Engine::builder(catalog).build().unwrap());
    let grants = vec![Grant::allow(
        "g",
        SubjectMatcher::user("alice"),
        "project.view",
        TargetSelector::kind("project"),
    )];
    let realtime = Realtime::new(hub).with_provider(Arc::new(EngineProvider::new(engine, grants)));
    Router::new()
        .route("/events", get(sse))
        .route("/ws", get(ws))
        .with_state(realtime)
}

async fn next_frame(body: &mut Body) -> String {
    let frame = tokio::time::timeout(Duration::from_secs(2), body.frame())
        .await
        .expect("quadro SSE")
        .expect("corpo aberto")
        .unwrap();
    String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap()
}

#[tokio::test]
async fn sse_streams_capabilities_and_changes() {
    let hub = Hub::new();
    let response = app(hub.clone())
        .oneshot(
            axum::http::Request::get("/events?scope=project:p1/org:o1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut body = response.into_body();
    assert!(next_frame(&mut body).await.starts_with("event: hello"));
    assert!(next_frame(&mut body).await.starts_with("event: capabilities"));

    hub.publish(Change::grants(Anchor::new("org", "o1"))).await.unwrap();
    assert!(next_frame(&mut body).await.starts_with("event: change"));
    assert!(next_frame(&mut body).await.starts_with("event: capabilities"));
}

#[tokio::test]
async fn websocket_accepts_watch_and_pushes_updates() {
    let hub = Hub::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app(hub.clone())).into_future());

    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .unwrap();
    assert!(matches!(recv(&mut socket).await, ServerMessage::Hello { .. }));

    socket
        .send(tokio_tungstenite::tungstenite::Message::text(
            r#"{"type":"watch","scopes":[{"path":[{"kind":"project","id":"p1"},{"kind":"org","id":"o1"}]}]}"#,
        ))
        .await
        .unwrap();
    match recv(&mut socket).await {
        ServerMessage::Capabilities { set, .. } => assert_eq!(set.grants.len(), 1),
        other => panic!("{other:?}"),
    }
    hub.publish(Change::grants(Anchor::new("project", "p1"))).await.unwrap();
    assert!(matches!(recv(&mut socket).await, ServerMessage::Change { .. }));
    assert!(matches!(recv(&mut socket).await, ServerMessage::Capabilities { .. }));
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn recv(socket: &mut Socket) -> ServerMessage {
    let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("mensagem")
        .unwrap()
        .unwrap();
    serde_json::from_str(frame.to_text().unwrap()).unwrap()
}
