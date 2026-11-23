use std::sync::Arc;

use async_trait::async_trait;
use themis::{CapabilitySet, Context, Engine, Grant, Resource, Subject};

use crate::cache::CapabilityCache;
use crate::hub::now_ms;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Computes the capabilities a session sends to the client.
#[async_trait]
pub trait CapabilityProvider: Send + Sync + 'static {
    async fn capabilities(&self, subject: &Subject, scope: &Resource) -> Result<CapabilitySet, BoxError>;

    /// Like [`CapabilityProvider::capabilities`], plus the instant the set was evaluated at and the
    /// next moment a grant or role assignment starts or stops being in force. Sessions schedule the
    /// expiry notice from it. The default derives the boundary from the returned set, which misses
    /// grants that start later; a provider that knows its candidate grants should override it.
    async fn evaluate(&self, subject: &Subject, scope: &Resource) -> Result<Evaluation, BoxError> {
        let evaluated_at = self.now_ms();
        let set = self.capabilities(subject, scope).await?;
        let next_boundary = set.next_boundary(evaluated_at);
        Ok(Evaluation {
            set,
            evaluated_at,
            next_boundary,
        })
    }

    /// The instant, in milliseconds since the Unix epoch, that `capabilities` evaluates validity
    /// windows at. Sessions use it to schedule the expiry notice. Defaults to the system clock.
    fn now_ms(&self) -> u64 {
        now_ms()
    }
}

/// Capabilities with the validity information a session needs to schedule its next recompute.
#[derive(Debug, Clone, PartialEq)]
pub struct Evaluation {
    pub set: CapabilitySet,
    /// Instant the set was evaluated at, milliseconds since the Unix epoch.
    pub evaluated_at: u64,
    /// Next instant after `evaluated_at` at which the set goes stale; `None` when it never does.
    pub next_boundary: Option<u64>,
}

/// Source of the current instant, in milliseconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Fetches the candidate grants of a subject in a scope (database, service, file).
///
/// Return the grants that start later too, and drop at most the ones that already expired: the
/// provider schedules the recompute at each start, and a start the loader filtered out never
/// triggers one. The engine applies the validity window itself, so a grant that has not started
/// is not granted. With the `themis-postgres` crate, filter with `candidate_predicate`, not
/// `window_predicate`.
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
    clock: Clock,
}

impl<L: GrantLoader> EngineProvider<L> {
    pub fn new(engine: Arc<Engine>, loader: L) -> Self {
        Self {
            engine,
            loader,
            cache: None,
            clock: Arc::new(now_ms),
        }
    }

    /// Replaces the system clock that decides which validity windows are open, for tests and for
    /// deployments that keep their own time source.
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Remember to register the same cache on the hub (`hub.on_change(cache.clone())`).
    ///
    /// The cache checks each entry's boundary against the system wall clock when it serves it, so
    /// a clock set with [`EngineProvider::with_clock`] must count milliseconds since the Unix epoch.
    pub fn with_cache(mut self, cache: Arc<CapabilityCache>) -> Self {
        self.cache = Some(cache);
        self
    }
}

#[async_trait]
impl<L: GrantLoader> CapabilityProvider for EngineProvider<L> {
    async fn capabilities(&self, subject: &Subject, scope: &Resource) -> Result<CapabilitySet, BoxError> {
        Ok(self.evaluate(subject, scope).await?.set)
    }

    async fn evaluate(&self, subject: &Subject, scope: &Resource) -> Result<Evaluation, BoxError> {
        let now = (self.clock)();
        if let Some((set, next_boundary)) = self.cache.as_ref().and_then(|c| c.get_with_boundary(subject, scope)) {
            return Ok(Evaluation {
                set,
                evaluated_at: now,
                next_boundary,
            });
        }
        let grants = self.loader.load(subject, scope).await?;
        let set = self.engine.capabilities(&Context::new(&grants).at(now), subject, scope);
        // From the candidates, not from the set: a grant that starts later is not in the set yet.
        let next_boundary = themis::next_boundary(now, &grants, &subject.roles);
        if let Some(cache) = &self.cache {
            // Measured when the entry is stored, not when it was evaluated: the TTL counts from the
            // insert, so time spent loading must come off the lifetime.
            cache.insert_with_boundary(subject, scope, set.clone(), next_boundary, (self.clock)());
        }
        Ok(Evaluation {
            set,
            evaluated_at: now,
            next_boundary,
        })
    }

    fn now_ms(&self) -> u64 {
        (self.clock)()
    }
}
