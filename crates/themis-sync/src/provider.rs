use std::sync::Arc;

use async_trait::async_trait;
use themis::{CapabilitySet, Context, Engine, Grant, Resource, Subject};

use crate::cache::CapabilityCache;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Calcula as capacidades que uma sessão envia ao cliente.
#[async_trait]
pub trait CapabilityProvider: Send + Sync + 'static {
    async fn capabilities(&self, subject: &Subject, scope: &Resource) -> Result<CapabilitySet, BoxError>;
}

/// Busca os grants candidatos de um sujeito num escopo (banco, serviço, arquivo).
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

/// [`CapabilityProvider`] padrão: carrega os grants pelo [`GrantLoader`], filtra pelo
/// [`Engine::capabilities`] e guarda no [`CapabilityCache`], se houver.
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

    /// Lembre de registrar o mesmo cache no hub (`hub.on_change(cache.clone())`).
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
