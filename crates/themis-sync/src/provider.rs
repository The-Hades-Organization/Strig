use std::sync::Arc;

use async_trait::async_trait;
use themis::{CapabilitySet, Context, Engine, Grant, Resource, Subject};

use crate::cache::CapabilityCache;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Computes the capabilities a session sends to the client.
#[async_trait]
pub trait CapabilityProvider: Send + Sync + 'static {
    async fn capabilities(&self, subject: &Subject, scope: &Resource) -> Result<CapabilitySet, BoxError>;
}

/// Fetches the candidate grants of a subject in a scope (database, service, file).
#[async_trait]
pub trait GrantLoader: Send + Sync + 'static {
    async fn load(&self, subject: &Subject, scope: &Resource) -> Result<Vec<Grant>, BoxError>;
}

#[async_trait]
impl GrantLoader for Vec<Grant> {
    async fn load(&self, _: &Subject, _: &Resource) -> Result<Vec<Grant>, BoxError> {
        Ok(self.clone())
    }
}

/// Default [`CapabilityProvider`]: loads the grants through the [`GrantLoader`], filters them with
/// [`Engine::capabilities`] and stores the result in the [`CapabilityCache`], if there is one.
pub struct EngineProvider<L> {
    engine: Arc<Engine>,
    loader: L,
    cache: Option<Arc<CapabilityCache>>,
}

impl<L: GrantLoader> EngineProvider<L> {
    pub fn new(engine: Arc<Engine>, loader: L) -> Self {
        Self {
            engine,
            loader,
            cache: None,
        }
    }

    /// Remember to register the same cache on the hub (`hub.on_change(cache.clone())`).
    pub fn with_cache(mut self, cache: Arc<CapabilityCache>) -> Self {
        self.cache = Some(cache);
        self
    }
}

#[async_trait]
impl<L: GrantLoader> CapabilityProvider for EngineProvider<L> {
    async fn capabilities(&self, subject: &Subject, scope: &Resource) -> Result<CapabilitySet, BoxError> {
        if let Some(cached) = self.cache.as_ref().and_then(|c| c.get(subject, scope)) {
            return Ok(cached);
        }
        let grants = self.loader.load(subject, scope).await?;
        let set = self.engine.capabilities(&Context::new(&grants), subject, scope);
        if let Some(cache) = &self.cache {
            cache.insert(subject, scope, set.clone());
        }
        Ok(set)
    }
}
