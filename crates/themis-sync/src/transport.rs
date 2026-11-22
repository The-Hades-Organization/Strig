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

/// Carries changes between instances of the application. Redis pub/sub, Postgres `LISTEN/NOTIFY`,
/// NATS, Kafka or a broker of your own plug in by implementing this trait.
///
/// Delivery is "at most once": the hub covers losses by emitting [`crate::ChangeKind::Resync`]
/// when the stream drops and comes back.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    fn name(&self) -> &str;

    async fn publish(&self, change: &Change) -> Result<(), TransportError>;

    /// Opens a stream with the changes published by any instance, including this one.
    /// Ends, or returns an error, when the connection drops; the hub reopens it.
    async fn subscribe(&self) -> Result<ChangeStream, TransportError>;
}

/// In-memory transport: clones share the same channel. Useful for tests and for
/// running several hubs in the same process.
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
