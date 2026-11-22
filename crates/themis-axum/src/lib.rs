//! Axum SSE and WebSocket routes on top of [`themis_sync::Session`].
//!
//! Authentication stays with the application: your handler identifies the subject and calls
//! [`Realtime::sse`] or [`Realtime::websocket`].
//!
//! See the [repository README](https://github.com/The-Hades-Organization/Themis) for the full guide.
//!
//! ```no_run
//! use axum::{Router, extract::{Query, State, WebSocketUpgrade}, routing::get, response::IntoResponse};
//! use themis::Subject;
//! use themis_axum::Realtime;
//! use themis_sync::scope_from_str;
//!
//! #[derive(serde::Deserialize)]
//! struct Params { scope: String }
//!
//! async fn sse(State(rt): State<Realtime>, Query(p): Query<Params>) -> impl IntoResponse {
//!     let subject = Subject::user("alice"); // comes from your authentication middleware
//!     rt.sse(subject, vec![scope_from_str(&p.scope)])
//! }
//!
//! async fn ws(State(rt): State<Realtime>, upgrade: WebSocketUpgrade) -> impl IntoResponse {
//!     rt.websocket(upgrade, Subject::user("alice"), Vec::new())
//! }
//!
//! # fn app(rt: Realtime) -> Router {
//! Router::new().route("/permissions/events", get(sse)).route("/permissions/ws", get(ws)).with_state(rt)
//! # }
//! ```

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, Stream, StreamExt};
use themis::{Resource, Subject};
use themis_sync::{CapabilityProvider, Hub, ServerMessage, Session, SessionOptions};

/// Hub, capability provider and session options shared by the routes.
#[derive(Clone)]
pub struct Realtime {
    hub: Hub,
    provider: Option<Arc<dyn CapabilityProvider>>,
    options: SessionOptions,
}

impl Realtime {
    pub fn new(hub: Hub) -> Self {
        Self {
            hub,
            provider: None,
            options: SessionOptions::default(),
        }
    }

    /// With a provider, the session sends the capabilities of each scope and resends them on every change.
    pub fn with_provider(mut self, provider: Arc<dyn CapabilityProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn with_options(mut self, options: SessionOptions) -> Self {
        self.options = options;
        self
    }

    pub fn hub(&self) -> &Hub {
        &self.hub
    }

    /// `text/event-stream` response. SSE is one-way: the scopes are set when the connection opens.
    pub fn sse(
        &self,
        subject: Subject,
        scopes: Vec<Resource>,
    ) -> Sse<impl Stream<Item = Result<Event, Infallible>> + use<>> {
        let (_control, stream) = Session::open(&self.hub, subject, scopes, self.provider.clone(), self.options.clone());
        Sse::new(stream.map(|message| Ok(to_event(&message))))
    }

    /// Performs the upgrade and binds the socket to the session. Once connected, the client can send
    /// `watch`, `unwatch` and `refresh`.
    pub fn websocket(&self, upgrade: WebSocketUpgrade, subject: Subject, scopes: Vec<Resource>) -> Response {
        let realtime = self.clone();
        upgrade
            .on_upgrade(move |socket| realtime.serve_socket(socket, subject, scopes))
            .into_response()
    }

    async fn serve_socket(self, socket: WebSocket, subject: Subject, scopes: Vec<Resource>) {
        let (control, mut outgoing) = Session::open(&self.hub, subject, scopes, self.provider, self.options);
        let (mut sink, mut incoming) = socket.split();
        loop {
            tokio::select! {
                message = outgoing.next() => {
                    let Some(message) = message else { break };
                    if sink.send(Message::Text(message.to_json().into())).await.is_err() {
                        break;
                    }
                }
                frame = incoming.next() => match frame {
                    Some(Ok(Message::Text(text))) => match control.handle_text(text.as_str()).await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            let reply = ServerMessage::Error { message: error.to_string() };
                            if sink.send(Message::Text(reply.to_json().into())).await.is_err() {
                                break;
                            }
                        }
                    },
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                },
            }
        }
        let _ = sink.close().await;
    }
}

fn to_event(message: &ServerMessage) -> Event {
    Event::default().event(message.event_name()).data(message.to_json())
}
