use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::change::Change;
use crate::transport::{Transport, TransportError};

/// Recebe cada mudança entregue ao hub, de forma síncrona (invalidação de cache, métrica).
pub trait ChangeSink: Send + Sync {
    fn on_change(&self, change: &Change);
}

impl<F: Fn(&Change) + Send + Sync> ChangeSink for F {
    fn on_change(&self, change: &Change) {
        self(change);
    }
}

struct Inner {
    origin: String,
    seq: AtomicU64,
    local: broadcast::Sender<Change>,
    transport: Option<Arc<dyn Transport>>,
    sinks: RwLock<Vec<Arc<dyn ChangeSink>>>,
}

/// Ponto único de mudanças de permissão de uma instância.
///
/// `publish` entrega na hora aos assinantes locais (sessões SSE/WebSocket, caches) e manda
/// pelo transporte para as outras instâncias. [`Hub::spawn_relay`] traz o que as outras
/// publicam, descartando o eco do próprio nó.
#[derive(Clone)]
pub struct Hub {
    inner: Arc<Inner>,
}

pub struct HubBuilder {
    capacity: usize,
    origin: Option<String>,
    transport: Option<Arc<dyn Transport>>,
}

impl HubBuilder {
    /// Mudanças retidas para assinantes lentos antes de eles receberem `Resync`.
    pub fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    /// Identificador do nó. Padrão: aleatório.
    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    pub fn transport(mut self, transport: impl Transport) -> Self {
        self.transport = Some(Arc::new(transport));
        self
    }

    pub fn shared_transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn build(self) -> Hub {
        let (local, _) = broadcast::channel(self.capacity);
        Hub {
            inner: Arc::new(Inner {
                origin: self.origin.unwrap_or_else(random_origin),
                seq: AtomicU64::new(0),
                local,
                transport: self.transport,
                sinks: RwLock::new(Vec::new()),
            }),
        }
    }
}

fn random_origin() -> String {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(now_ms() as u128);
    hasher.write_u32(std::process::id());
    format!("{:016x}", hasher.finish())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Default for Hub {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Hub {
    /// Hub só local, sem transporte.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> HubBuilder {
        HubBuilder {
            capacity: 1024,
            origin: None,
            transport: None,
        }
    }

    pub fn origin(&self) -> &str {
        &self.inner.origin
    }

    pub fn transport_name(&self) -> Option<&str> {
        self.inner.transport.as_deref().map(Transport::name)
    }

    /// Carimba origem, sequência e hora, entrega localmente e publica no transporte. A entrega
    /// local acontece mesmo se o transporte falhar; o erro volta para quem publicou.
    pub async fn publish(&self, mut change: Change) -> Result<Change, TransportError> {
        change.origin = self.inner.origin.clone();
        change.seq = self.inner.seq.fetch_add(1, Ordering::Relaxed) + 1;
        if change.at == 0 {
            change.at = now_ms();
        }
        self.deliver(&change);
        if let Some(transport) = &self.inner.transport {
            transport.publish(&change).await?;
        }
        Ok(change)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Change> {
        self.inner.local.subscribe()
    }

    pub fn on_change(&self, sink: Arc<dyn ChangeSink>) {
        self.inner
            .sinks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(sink);
    }

    /// Entrega uma mudança só neste nó, sem transporte.
    pub fn deliver(&self, change: &Change) {
        let sinks = self
            .inner
            .sinks
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        for sink in sinks {
            sink.on_change(change);
        }
        let _ = self.inner.local.send(change.clone());
    }

    /// Escuta o transporte em segundo plano e entrega aqui o que as outras instâncias
    /// publicam. Reconecta com backoff exponencial (100 ms até 5 s) e emite `Resync` a cada
    /// reconexão, porque o que foi publicado no intervalo se perdeu. Sem transporte, não faz
    /// nada. O relay para quando o [`RelayHandle`] é descartado.
    pub fn spawn_relay(&self) -> RelayHandle {
        let hub = self.clone();
        let task = tokio::spawn(async move {
            let Some(transport) = hub.inner.transport.clone() else {
                return;
            };
            let mut backoff = Duration::from_millis(100);
            let mut connected_before = false;
            loop {
                if let Ok(mut stream) = transport.subscribe().await {
                    if connected_before {
                        hub.deliver(&Change::resync());
                    }
                    connected_before = true;
                    backoff = Duration::from_millis(100);
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(change) if change.origin == hub.inner.origin => {}
                            Ok(change) => hub.deliver(&change),
                            Err(TransportError::Decode(_)) => {}
                            Err(_) => break,
                        }
                    }
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        });
        RelayHandle { task }
    }
}

/// Mantém o relay vivo; descartar para parar.
pub struct RelayHandle {
    task: JoinHandle<()>,
}

impl RelayHandle {
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::ChangeKind;
    use crate::transport::MemoryTransport;
    use std::sync::Mutex;
    use themis::Anchor;

    #[tokio::test]
    async fn local_delivery_and_sinks() {
        let hub = Hub::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        hub.on_change(Arc::new(move |c: &Change| log.lock().unwrap().push(c.seq)));
        let mut rx = hub.subscribe();
        let sent = hub.publish(Change::grants(Anchor::new("org", "o1"))).await.unwrap();
        assert_eq!(sent.seq, 1);
        assert_eq!(rx.recv().await.unwrap(), sent);
        assert_eq!(*seen.lock().unwrap(), [1]);
    }

    #[tokio::test]
    async fn relay_crosses_instances_without_echo() {
        let transport = MemoryTransport::default();
        let a = Hub::builder().origin("a").transport(transport.clone()).build();
        let b = Hub::builder().origin("b").transport(transport).build();
        let _ra = a.spawn_relay();
        let _rb = b.spawn_relay();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut at_a = a.subscribe();
        let mut at_b = b.subscribe();
        a.publish(Change::grants(Anchor::new("org", "o1"))).await.unwrap();

        let got = tokio::time::timeout(Duration::from_secs(1), at_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.origin, "a");
        assert_eq!(at_a.recv().await.unwrap().origin, "a");
        let echo = tokio::time::timeout(Duration::from_millis(100), at_a.recv()).await;
        assert!(echo.is_err(), "o eco do próprio nó não pode voltar");
    }

    struct Flaky {
        inner: MemoryTransport,
        fails: AtomicU64,
    }

    #[async_trait::async_trait]
    impl Transport for Flaky {
        fn name(&self) -> &str {
            "flaky"
        }
        async fn publish(&self, change: &Change) -> Result<(), TransportError> {
            self.inner.publish(change).await
        }
        async fn subscribe(&self) -> Result<crate::transport::ChangeStream, TransportError> {
            if self.fails.fetch_add(1, Ordering::SeqCst) == 0 {
                let once = futures_util::stream::iter([Err(TransportError::Closed)]);
                return Ok(Box::pin(once));
            }
            self.inner.subscribe().await
        }
    }

    #[tokio::test]
    async fn reconnect_emits_resync() {
        let hub = Hub::builder()
            .transport(Flaky {
                inner: MemoryTransport::default(),
                fails: AtomicU64::new(0),
            })
            .build();
        let mut rx = hub.subscribe();
        let _relay = hub.spawn_relay();
        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.kind, ChangeKind::Resync);
    }
}
