//! Sessão de um cliente conectado, independente de framework HTTP.
//!
//! [`Session::open`] devolve um stream de [`ServerMessage`] para escrever no SSE ou no
//! WebSocket e um [`SessionControl`] para repassar as mensagens que o cliente manda (só no
//! WebSocket). O adaptador do framework só faz a ponte; a lógica fica aqui.

use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use themis::{Resource, Subject};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{Instant, Interval, interval_at};
use tokio_stream::wrappers::ReceiverStream;

use crate::change::{Change, ChangeKind};
use crate::hub::Hub;
use crate::protocol::{ClientMessage, ServerMessage};
use crate::provider::CapabilityProvider;

#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// Intervalo do `ping`. Mantém proxies e balanceadores sem fechar a conexão ociosa.
    pub heartbeat: Option<Duration>,
    /// Mensagens enfileiradas para um cliente lento antes de a sessão esperar por ele.
    pub buffer: usize,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            heartbeat: Some(Duration::from_secs(25)),
            buffer: 64,
        }
    }
}

pub type SessionStream = ReceiverStream<ServerMessage>;

/// Canal para as mensagens que o cliente envia.
#[derive(Clone)]
pub struct SessionControl {
    tx: mpsc::Sender<ClientMessage>,
}

impl SessionControl {
    /// Devolve `false` se a sessão já terminou.
    pub async fn send(&self, message: ClientMessage) -> bool {
        self.tx.send(message).await.is_ok()
    }

    /// Repassa um quadro de texto do WebSocket. JSON inválido volta como erro e a sessão segue.
    pub async fn handle_text(&self, text: &str) -> Result<bool, serde_json::Error> {
        Ok(self.send(ClientMessage::from_json(text)?).await)
    }
}

pub struct Session;

impl Session {
    /// Abre a sessão de `subject` observando `scopes`. Sem `provider`, o cliente recebe só os
    /// avisos de mudança e recarrega por conta própria. A sessão termina quando o stream é
    /// descartado.
    pub fn open(
        hub: &Hub,
        subject: Subject,
        scopes: Vec<Resource>,
        provider: Option<Arc<dyn CapabilityProvider>>,
        options: SessionOptions,
    ) -> (SessionControl, SessionStream) {
        let changes = hub.subscribe();
        let (out, stream) = mpsc::channel(options.buffer.max(1));
        let (tx, control) = mpsc::channel(16);
        let heartbeat = options
            .heartbeat
            .map(|period| interval_at(Instant::now() + period, period));
        let worker = Worker {
            out,
            subject,
            scopes,
            provider,
        };
        tokio::spawn(worker.run(hub.origin().to_string(), changes, control, heartbeat));
        (SessionControl { tx }, ReceiverStream::new(stream))
    }
}

struct Worker {
    out: mpsc::Sender<ServerMessage>,
    subject: Subject,
    scopes: Vec<Resource>,
    provider: Option<Arc<dyn CapabilityProvider>>,
}

async fn tick(heartbeat: &mut Option<Interval>) {
    match heartbeat {
        Some(interval) => {
            interval.tick().await;
        }
        None => pending().await,
    }
}

impl Worker {
    async fn run(
        mut self,
        origin: String,
        mut changes: broadcast::Receiver<Change>,
        mut control: mpsc::Receiver<ClientMessage>,
        mut heartbeat: Option<Interval>,
    ) {
        let hello = ServerMessage::Hello {
            origin,
            subject: self.subject.id.clone(),
        };
        if !self.send(hello).await || !self.push_all().await {
            return;
        }
        let mut control_open = true;
        loop {
            let alive = tokio::select! {
                received = changes.recv() => match received {
                    Err(RecvError::Closed) => false,
                    first => self.on_changes(first.ok(), &mut changes).await,
                },
                message = control.recv(), if control_open => match message {
                    None => {
                        control_open = false;
                        true
                    }
                    Some(message) => self.on_client(message).await,
                },
                _ = tick(&mut heartbeat) => self.send(ServerMessage::Ping).await,
            };
            if !alive {
                return;
            }
        }
    }

    async fn send(&self, message: ServerMessage) -> bool {
        self.out.send(message).await.is_ok()
    }

    async fn push(&self, scope: &Resource) -> bool {
        let Some(provider) = &self.provider else {
            return true;
        };
        let message = match provider.capabilities(&self.subject, scope).await {
            Ok(set) => ServerMessage::Capabilities {
                scope: scope.clone(),
                set,
            },
            Err(error) => ServerMessage::Error {
                message: error.to_string(),
            },
        };
        self.send(message).await
    }

    async fn push_all(&self) -> bool {
        for scope in &self.scopes {
            if !self.push(scope).await {
                return false;
            }
        }
        true
    }

    /// Junta as mudanças já enfileiradas e recalcula cada escopo afetado uma vez só.
    async fn on_changes(&mut self, first: Option<Change>, changes: &mut broadcast::Receiver<Change>) -> bool {
        let mut batch: Vec<Change> = first.into_iter().collect();
        let mut lost = batch.is_empty();
        loop {
            match changes.try_recv() {
                Ok(change) => batch.push(change),
                Err(TryRecvError::Lagged(_)) => lost = true,
                Err(_) => break,
            }
        }
        if lost || batch.iter().any(|c| c.kind == ChangeKind::Resync) {
            return self.send(ServerMessage::Resync).await && self.push_all().await;
        }
        let subject = self.subject.id.clone();
        let mut affected = vec![false; self.scopes.len()];
        for change in batch {
            let mut relevant = false;
            for (i, scope) in self.scopes.iter().enumerate() {
                if change.affects(subject.as_deref(), scope) {
                    affected[i] = true;
                    relevant = true;
                }
            }
            if relevant && !self.send(ServerMessage::Change { change }).await {
                return false;
            }
        }
        for (i, scope) in self.scopes.iter().enumerate() {
            if affected[i] && !self.push(scope).await {
                return false;
            }
        }
        true
    }

    async fn on_client(&mut self, message: ClientMessage) -> bool {
        match message {
            ClientMessage::Watch { scopes } => {
                for scope in scopes {
                    if self.scopes.contains(&scope) {
                        continue;
                    }
                    self.scopes.push(scope.clone());
                    if !self.push(&scope).await {
                        return false;
                    }
                }
                true
            }
            ClientMessage::Unwatch { scopes } => {
                self.scopes.retain(|s| !scopes.contains(s));
                true
            }
            ClientMessage::Refresh => self.push_all().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::EngineProvider;
    use futures_util::StreamExt;
    use themis::{Anchor, Catalog, Engine, Grant, PermissionDef, SubjectMatcher, TargetSelector};

    fn provider(grants: Vec<Grant>) -> Arc<dyn CapabilityProvider> {
        let catalog = Catalog::builder()
            .target_kinds(["project"])
            .broad_target("org")
            .permission(PermissionDef::new("project.view").targets(["project"]))
            .build()
            .unwrap();
        let engine = Arc::new(Engine::builder(catalog).build().unwrap());
        Arc::new(EngineProvider::new(engine, grants))
    }

    async fn next(stream: &mut SessionStream) -> ServerMessage {
        tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("mensagem")
            .expect("stream aberto")
    }

    #[tokio::test]
    async fn pushes_capabilities_then_changes() {
        let hub = Hub::new();
        let grants = vec![Grant::allow(
            "g",
            SubjectMatcher::user("alice"),
            "project.view",
            TargetSelector::kind("project"),
        )];
        let p1 = Resource::new("project", "p1").within("org", "o1");
        let (control, mut stream) = Session::open(
            &hub,
            Subject::user("alice"),
            vec![p1.clone()],
            Some(provider(grants)),
            SessionOptions::default(),
        );
        assert!(matches!(next(&mut stream).await, ServerMessage::Hello { .. }));
        match next(&mut stream).await {
            ServerMessage::Capabilities { scope, set } => {
                assert_eq!(scope, p1);
                assert_eq!(set.grants.len(), 1);
            }
            other => panic!("{other:?}"),
        }

        hub.publish(Change::grants(Anchor::new("org", "o2"))).await.unwrap();
        hub.publish(Change::grants(Anchor::new("org", "o1"))).await.unwrap();
        match next(&mut stream).await {
            ServerMessage::Change { change } => assert_eq!(change.scope, Anchor::new("org", "o1")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(next(&mut stream).await, ServerMessage::Capabilities { .. }));

        let p2 = Resource::new("project", "p2");
        assert!(
            control
                .send(ClientMessage::Watch {
                    scopes: vec![p2.clone()]
                })
                .await
        );
        match next(&mut stream).await {
            ServerMessage::Capabilities { scope, .. } => assert_eq!(scope, p2),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn heartbeat_and_resync() {
        let hub = Hub::new();
        let options = SessionOptions {
            heartbeat: Some(Duration::from_millis(30)),
            buffer: 8,
        };
        let (_control, mut stream) = Session::open(&hub, Subject::anonymous(), Vec::new(), None, options);
        assert!(matches!(next(&mut stream).await, ServerMessage::Hello { .. }));
        assert_eq!(next(&mut stream).await, ServerMessage::Ping);
        hub.publish(Change::resync()).await.unwrap();
        assert_eq!(next(&mut stream).await, ServerMessage::Resync);
    }
}
