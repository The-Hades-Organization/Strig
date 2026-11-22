//! Redis pub/sub transport for the [`themis_sync::Hub`].
//!
//! See the [repository README](https://github.com/The-Hades-Organization/Themis) for the full guide.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use themis_sync::Hub;
//! use themis_redis::RedisTransport;
//!
//! let hub = Hub::builder()
//!     .transport(RedisTransport::new("redis://127.0.0.1/", "themis:changes")?)
//!     .build();
//! let _relay = hub.spawn_relay();
//! # Ok(()) }
//! ```
//!
//! Publishing uses a `ConnectionManager`, which reconnects on its own. Each `subscribe` opens a
//! dedicated pub/sub connection; when it drops, the stream ends and the hub reopens it and emits
//! `Resync`.

use async_trait::async_trait;
use futures_util::StreamExt;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use themis_sync::{Change, ChangeStream, Transport, TransportError};
use tokio::sync::OnceCell;

pub struct RedisTransport {
    client: Client,
    channel: String,
    publisher: OnceCell<ConnectionManager>,
}

fn connection(error: redis::RedisError) -> TransportError {
    TransportError::Connection(error.to_string())
}

impl RedisTransport {
    pub fn new(url: &str, channel: impl Into<String>) -> Result<Self, TransportError> {
        Ok(Self::from_client(Client::open(url).map_err(connection)?, channel))
    }

    pub fn from_client(client: Client, channel: impl Into<String>) -> Self {
        Self {
            client,
            channel: channel.into(),
            publisher: OnceCell::new(),
        }
    }

    pub fn channel(&self) -> &str {
        &self.channel
    }

    async fn publisher(&self) -> Result<ConnectionManager, TransportError> {
        self.publisher
            .get_or_try_init(|| ConnectionManager::new(self.client.clone()))
            .await
            .cloned()
            .map_err(connection)
    }
}

#[async_trait]
impl Transport for RedisTransport {
    fn name(&self) -> &str {
        "redis"
    }

    async fn publish(&self, change: &Change) -> Result<(), TransportError> {
        let mut con = self.publisher().await?;
        con.publish::<_, _, ()>(&self.channel, change.to_json())
            .await
            .map_err(connection)
    }

    async fn subscribe(&self) -> Result<ChangeStream, TransportError> {
        let mut pubsub = self.client.get_async_pubsub().await.map_err(connection)?;
        pubsub.subscribe(&self.channel).await.map_err(connection)?;
        let stream = pubsub.into_on_message().map(|message| {
            let payload: String = message
                .get_payload()
                .map_err(|e| TransportError::Decode(e.to_string()))?;
            Change::from_json(&payload).map_err(|e| TransportError::Decode(e.to_string()))
        });
        Ok(Box::pin(stream))
    }
}
