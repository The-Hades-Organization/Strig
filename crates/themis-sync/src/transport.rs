use std::pin::Pin;

use async_trait::async_trait;
use futures_util::Stream;
use tokio::sync::broadcast;

use crate::change::Change;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("conexão: {0}")]
    Connection(String),
    #[error("mensagem inválida: {0}")]
    Decode(String),
    #[error("transporte fechado")]
    Closed,
}

pub type ChangeStream = Pin<Box<dyn Stream<Item = Result<Change, TransportError>> + Send>>;

/// Leva as mudanças entre instâncias da aplicação. Redis pub/sub, Postgres `LISTEN/NOTIFY`,
/// NATS, Kafka ou um broker próprio entram implementando este trait.
///
/// A entrega é "no máximo uma vez": o hub cobre perdas emitindo [`crate::ChangeKind::Resync`]
/// quando o stream cai e volta.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    fn name(&self) -> &str;

    async fn publish(&self, change: &Change) -> Result<(), TransportError>;

    /// Abre um stream com as mudanças publicadas por qualquer instância, inclusive esta.
    /// Termina, ou devolve erro, quando a conexão cai; o hub reabre.
    async fn subscribe(&self) -> Result<ChangeStream, TransportError>;
}

/// Transporte em memória: clones compartilham o mesmo canal. Serve para testes e para
/// rodar vários hubs no mesmo processo.
#[derive(Clone)]
pub struct MemoryTransport {
    bus: broadcast::Sender<Change>,
}

impl MemoryTransport {
    pub fn new(capacity: usize) -> Self {
        let (bus, _) = broadcast::channel(capacity.max(1));
        Self { bus }
    }
}

impl Default for MemoryTransport {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[async_trait]
impl Transport for MemoryTransport {
    fn name(&self) -> &str {
        "memory"
    }

    async fn publish(&self, change: &Change) -> Result<(), TransportError> {
        let _ = self.bus.send(change.clone());
        Ok(())
    }

    async fn subscribe(&self) -> Result<ChangeStream, TransportError> {
        use futures_util::StreamExt;
        use tokio_stream::wrappers::BroadcastStream;
        let stream = BroadcastStream::new(self.bus.subscribe())
            .map(|item| item.map_err(|lagged| TransportError::Connection(lagged.to_string())));
        Ok(Box::pin(stream))
    }
}
