//! Messages exchanged with the client over SSE or WebSocket, in JSON.
//!
//! Server → client ([`ServerMessage`]): `hello`, `capabilities`, `change`, `resync`,
//! `error`, `ping`. Client → server ([`ClientMessage`], WebSocket only): `watch`, `unwatch`,
//! `refresh`. Over SSE the type is also sent in the `event:` field.

use serde::{Deserialize, Serialize};
use strig::{CapabilitySet, Resource};

use crate::change::Change;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Hello {
        origin: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<String>,
    },
    /// Current grants of the subject for a watched scope. Replaces the previous set.
    Capabilities {
        scope: Resource,
        set: CapabilitySet,
    },
    /// A change that affects a watched scope.
    Change {
        change: Change,
    },
    /// The client lost changes: discard what it has and wait for new `capabilities`.
    Resync,
    Error {
        message: String,
    },
    Ping,
}

impl ServerMessage {
    pub fn event_name(&self) -> &'static str {
        match self {
            ServerMessage::Hello { .. } => "hello",
            ServerMessage::Capabilities { .. } => "capabilities",
            ServerMessage::Change { .. } => "change",
            ServerMessage::Resync => "resync",
            ServerMessage::Error { .. } => "error",
            ServerMessage::Ping => "ping",
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("ServerMessage sempre serializa")
    }

    /// Complete SSE frame (`event:`, `data:` and a blank line), ready to write to the
    /// body of the `text/event-stream` response.
    pub fn to_sse(&self) -> String {
        format!("event: {}\ndata: {}\n\n", self.event_name(), self.to_json())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Starts watching these scopes and receives the capabilities of each.
    Watch {
        scopes: Vec<Resource>,
    },
    Unwatch {
        scopes: Vec<Resource>,
    },
    /// Asks again for the capabilities of all the watched scopes.
    Refresh,
}

impl ClientMessage {
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

/// Scope as text, for query strings and SSE URLs: steps from the most specific to the
/// broadest, separated by `/`, each one `kind:id` or just `kind`
/// (`document:d1/project:p1/org:o1`).
pub fn scope_to_string(scope: &Resource) -> String {
    scope.path.iter().map(ToString::to_string).collect::<Vec<_>>().join("/")
}

pub fn scope_from_str(text: &str) -> Resource {
    let path = text
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| match segment.split_once(':') {
            Some((kind, id)) => strig::Anchor::new(kind, id),
            None => strig::Anchor::kind_only(segment),
        })
        .collect();
    Resource {
        path,
        attrs: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_text_round_trip() {
        let scope = Resource::new("document", "d1").within("project", "p1");
        assert_eq!(scope_to_string(&scope), "document:d1/project:p1");
        assert_eq!(scope_from_str("document:d1/project:p1"), scope);
    }

    #[test]
    fn sse_frame() {
        assert_eq!(
            ServerMessage::Ping.to_sse(),
            "event: ping\ndata: {\"type\":\"ping\"}\n\n"
        );
    }

    #[test]
    fn client_message_json() {
        let msg =
            ClientMessage::from_json(r#"{"type":"watch","scopes":[{"path":[{"kind":"project","id":"p1"}]}]}"#).unwrap();
        assert_eq!(
            msg,
            ClientMessage::Watch {
                scopes: vec![Resource::new("project", "p1")]
            }
        );
    }
}
