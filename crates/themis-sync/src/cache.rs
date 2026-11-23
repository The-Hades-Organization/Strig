//! Cache with a TTL and the capability cache that is invalidated through the [`crate::Hub`].
//!
//! The cache is an optimization: the application still revalidates on the server on every
//! privileged operation.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use themis::{CapabilitySet, Resource, Subject};

use crate::change::{Change, ChangeKind};
use crate::hub::{ChangeSink, now_ms};

struct Entry<V> {
    value: V,
    stored_at: Instant,
    /// `None` when the lifetime does not fit an `Instant`: the entry never expires by age.
    expires_at: Option<Instant>,
}

impl<V> Entry<V> {
    fn is_live(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|at| now < at)
    }
}

pub struct TtlCache<K, V> {
    ttl: Duration,
    capacity: usize,
    entries: Mutex<HashMap<K, Entry<V>>>,
}

impl<K: Eq + Hash + Clone, V: Clone> TtlCache<K, V> {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<K, Entry<V>>> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let entries = self.lock();
        let now = Instant::now();
        entries
            .get(key)
            .filter(|entry| entry.is_live(now))
            .map(|entry| entry.value.clone())
    }

    pub fn insert(&self, key: K, value: V) {
        self.insert_for(key, value, self.ttl);
    }

    /// Like [`TtlCache::insert`], but the entry lives for the shorter of the cache TTL and
    /// `max_age`. For a value that stops being valid at a known instant.
    pub fn insert_for(&self, key: K, value: V, max_age: Duration) {
        let mut entries = self.lock();
        let now = Instant::now();
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            entries.retain(|_, entry| entry.is_live(now));
            if entries.len() >= self.capacity
                && let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.stored_at)
                    .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key,
            Entry {
                value,
                stored_at: now,
                expires_at: now.checked_add(self.ttl.min(max_age)),
            },
        );
    }

    pub fn invalidate(&self, key: &K) {
        self.lock().remove(key);
    }

    /// Keeps only the entries for which `keep` returns `true`.
    pub fn retain(&self, keep: impl Fn(&K, &V) -> bool) {
        self.lock().retain(|key, entry| keep(key, &entry.value));
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

/// [`CapabilitySet`] per subject and scope. Registered on the hub with [`crate::Hub::on_change`],
/// it drops the entries a change affects.
///
/// An entry never outlives the next validity boundary of its set (a grant or role assignment that
/// starts or stops being in force), so a capability is not served after its `valid_until`.
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

    /// Stores a set computed just now, by the system clock. See [`CapabilityCache::insert_at`].
    pub fn insert(&self, subject: &Subject, scope: &Resource, set: CapabilitySet) {
        self.insert_at(subject, scope, set, now_ms());
    }

    /// Stores a set computed at `now_ms` (milliseconds since the Unix epoch), cutting the TTL at the
    /// set's next validity boundary.
    pub fn insert_at(&self, subject: &Subject, scope: &Resource, set: CapabilitySet, now_ms: u64) {
        let max_age = max_age(&set, now_ms);
        self.inner.insert_for(
            Self::key(subject, scope),
            (subject.id.clone(), scope.clone(), set),
            max_age,
        );
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

/// Time left until the set's next validity boundary; unlimited when nothing changes any more.
fn max_age(set: &CapabilitySet, now_ms: u64) -> Duration {
    set.next_boundary(now_ms)
        .map_or(Duration::MAX, |boundary| Duration::from_millis(boundary - now_ms))
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
    use themis::{Anchor, Grant, SubjectMatcher, TargetSelector};

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

    fn windowed_set(subject: &Subject, valid_until: u64) -> CapabilitySet {
        CapabilitySet {
            subject: subject.clone(),
            grants: vec![
                Grant::allow("g", SubjectMatcher::Any, "project.view", TargetSelector::global())
                    .valid_until(valid_until),
            ],
        }
    }

    #[test]
    fn ttl_is_cut_at_the_next_boundary() {
        let alice = Subject::user("alice");
        assert_eq!(max_age(&windowed_set(&alice, 1_050), 1_000), Duration::from_millis(50));
        let unbounded = CapabilitySet {
            subject: alice,
            grants: Vec::new(),
        };
        assert_eq!(max_age(&unbounded, 1_000), Duration::MAX);
    }

    #[test]
    fn entry_does_not_outlive_its_max_age() {
        let cache = TtlCache::new(Duration::from_secs(60), 4);
        cache.insert_for(1, "a", Duration::ZERO);
        cache.insert_for(2, "b", Duration::from_secs(120));
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some("b"));
    }

    #[test]
    fn capability_cache_drops_the_set_once_the_boundary_passes() {
        let cache = CapabilityCache::new(Duration::from_secs(60), 10);
        let alice = Subject::user("alice");
        let scope = Resource::new("project", "p1");
        cache.insert_at(&alice, &scope, windowed_set(&alice, 1_001), 1_000);
        std::thread::sleep(Duration::from_millis(30));
        assert!(cache.get(&alice, &scope).is_none(), "served a set past its valid_until");

        cache.insert_at(&alice, &scope, windowed_set(&alice, 1_000_000), 1_000);
        assert!(cache.get(&alice, &scope).is_some());
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
