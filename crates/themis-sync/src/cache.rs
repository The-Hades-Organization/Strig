//! Cache com TTL e o cache de capacidades que se invalida pelo [`crate::Hub`].
//!
//! O cache é uma otimização: a aplicação continua revalidando no servidor em toda operação
//! privilegiada.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use themis::{CapabilitySet, Resource, Subject};

use crate::change::{Change, ChangeKind};
use crate::hub::ChangeSink;

pub struct TtlCache<K, V> {
    ttl: Duration,
    capacity: usize,
    entries: Mutex<HashMap<K, (V, Instant)>>,
}

impl<K: Eq + Hash + Clone, V: Clone> TtlCache<K, V> {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<K, (V, Instant)>> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let entries = self.lock();
        entries
            .get(key)
            .filter(|(_, at)| at.elapsed() < self.ttl)
            .map(|(value, _)| value.clone())
    }

    pub fn insert(&self, key: K, value: V) {
        let mut entries = self.lock();
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            entries.retain(|_, (_, at)| at.elapsed() < self.ttl);
            if entries.len() >= self.capacity
                && let Some(oldest) = entries.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, (value, Instant::now()));
    }

    pub fn invalidate(&self, key: &K) {
        self.lock().remove(key);
    }

    /// Mantém só as entradas para as quais `keep` devolve `true`.
    pub fn retain(&self, keep: impl Fn(&K, &V) -> bool) {
        self.lock().retain(|key, (value, _)| keep(key, value));
    }

    pub fn clear(&self) {
        self.lock().clear();
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// [`CapabilitySet`] por sujeito e escopo. Registrado no hub com [`crate::Hub::on_change`],
/// descarta as entradas que uma mudança afeta.
pub struct CapabilityCache {
    inner: TtlCache<String, (Option<String>, Resource, CapabilitySet)>,
}

impl CapabilityCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: TtlCache::new(ttl, capacity),
        }
    }

    fn key(subject: &Subject, scope: &Resource) -> String {
        let path: Vec<String> = scope.path.iter().map(ToString::to_string).collect();
        format!(
            "{}:{}|{}",
            subject.kind,
            subject.id.as_deref().unwrap_or("-"),
            path.join("/")
        )
    }

    pub fn get(&self, subject: &Subject, scope: &Resource) -> Option<CapabilitySet> {
        self.inner.get(&Self::key(subject, scope)).map(|(_, _, set)| set)
    }

    pub fn insert(&self, subject: &Subject, scope: &Resource, set: CapabilitySet) {
        self.inner
            .insert(Self::key(subject, scope), (subject.id.clone(), scope.clone(), set));
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&self) {
        self.inner.clear();
    }
}

impl ChangeSink for CapabilityCache {
    fn on_change(&self, change: &Change) {
        if change.kind == ChangeKind::Resync {
            self.inner.clear();
            return;
        }
        self.inner
            .retain(|_, (subject, scope, _)| !change.affects(subject.as_deref(), scope));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use themis::Anchor;

    #[test]
    fn expires_and_evicts() {
        let cache = TtlCache::new(Duration::from_millis(0), 2);
        cache.insert(1, "a");
        assert_eq!(cache.get(&1), None);

        let cache = TtlCache::new(Duration::from_secs(60), 2);
        cache.insert(1, "a");
        cache.insert(2, "b");
        cache.insert(3, "c");
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&3), Some("c"));
    }

    #[test]
    fn change_drops_only_affected_entries() {
        let cache = CapabilityCache::new(Duration::from_secs(60), 100);
        let alice = Subject::user("alice");
        let p1 = Resource::new("project", "p1").within("org", "o1");
        let p2 = Resource::new("project", "p2").within("org", "o2");
        let empty = |s: &Subject| CapabilitySet {
            subject: s.clone(),
            grants: Vec::new(),
        };
        cache.insert(&alice, &p1, empty(&alice));
        cache.insert(&alice, &p2, empty(&alice));

        cache.on_change(&Change::grants(Anchor::new("org", "o1")));
        assert!(cache.get(&alice, &p1).is_none());
        assert!(cache.get(&alice, &p2).is_some());

        cache.on_change(&Change::roles("bob", Anchor::new("org", "o2")));
        assert!(cache.get(&alice, &p2).is_some());
        cache.on_change(&Change::roles("alice", Anchor::new("org", "o2")));
        assert!(cache.is_empty());
    }
}
