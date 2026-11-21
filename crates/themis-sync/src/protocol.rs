//! Mensagens trocadas com o cliente por SSE ou WebSocket, em JSON.
//!
//! Servidor → cliente ([`ServerMessage`]): `hello`, `capabilities`, `change`, `resync`,
//! `error`, `ping`. Cliente → servidor ([`ClientMessage`], só WebSocket): `watch`, `unwatch`,
//! `refresh`. No SSE o tipo vai também no campo `event:`.

use serde::{Deserialize, Serialize};
use themis::{CapabilitySet, Resource};

use crate::change::Change;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Hello {
        origin: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<String>,
    },
    /// Grants atuais do sujeito para um escopo observado. Substitui o conjunto anterior.
    Capabilities {
        scope: Resource,
        set: CapabilitySet,
    },
    /// Uma mudança que afeta um escopo observado.
    Change {
        change: Change,
    },
    /// O cliente perdeu mudanças: descarte o que tem e espere novos `capabilities`.
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

    /// Quadro SSE completo (`event:`, `data:` e linha em branco), pronto para escrever no
    /// corpo da resposta `text/event-stream`.
    pub fn to_sse(&self) -> String {
        format!("event: {}\ndata: {}\n\n", self.event_name(), self.to_json())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Passa a observar estes escopos e recebe as capacidades de cada um.
    Watch {
        scopes: Vec<Resource>,
    },
    Unwatch {
        scopes: Vec<Resource>,
    },
    /// Pede de novo as capacidades de todos os escopos observados.
    Refresh,
}

impl ClientMessage {
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

/// Escopo em forma de texto, para query string e URL de SSE: degraus do mais específico ao
/// mais amplo separados por `/`, cada um `tipo:id` ou só `tipo`
/// (`document:d1/project:p1/org:o1`).
pub fn scope_to_string(scope: &Resource) -> String {
    scope.path.iter().map(ToString::to_string).collect::<Vec<_>>().join("/")
}

pub fn scope_from_str(text: &str) -> Resource {
    let path = text
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| match segment.split_once(':') {
            Some((kind, id)) => themis::Anchor::new(kind, id),
            None => themis::Anchor::kind_only(segment),
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
