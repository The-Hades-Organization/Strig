use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::change::Change;
use crate::transport::{Transport, TransportError};

/// Receives every change delivered to the hub, synchronously (cache invalidation, metrics).
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
    expiries: Mutex<Expiries>,
    sessions: AtomicU64,
}

/// One pending expiry notice: the boundary and the subject it concerns.
type ExpiryKey = (u64, Option<String>);

/// Holder id of a caller that never releases its notice ([`Hub::schedule_expiry`]).
const UNRELEASED: u64 = 0;

/// Notices fired for the same key within this window count as repeats.
const REPEAT_WINDOW: Duration = Duration::from_secs(10);
/// Repeats of the same key that run at once before the next one is delayed.
const FREE_REPEATS: u32 = 2;
const REPEAT_BACKOFF: Duration = Duration::from_millis(100);
const MAX_REPEAT_BACKOFF: Duration = Duration::from_secs(5);

struct PendingExpiry {
    task: JoinHandle<()>,
    /// Who asked for the notice. The task is aborted when the last holder is released.
    holders: HashSet<u64>,
}

#[derive(Default)]
struct Expiries {
    pending: HashMap<ExpiryKey, PendingExpiry>,
    /// When a key last fired and how many times in a row, to slow down a loop that schedules the
    /// boundary that just fired again (a clock that does not advance).
    fired: HashMap<ExpiryKey, (Instant, u32)>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let expiries = self.expiries.get_mut().unwrap_or_else(|poisoned| poisoned.into_inner());
        for (_, pending) in expiries.pending.drain() {
            pending.task.abort();
        }
    }
}

/// Single point for permission changes of an instance.
///
/// `publish` delivers immediately to the local subscribers (SSE/WebSocket sessions, caches) and sends
/// through the transport to the other instances. [`Hub::spawn_relay`] brings in what the others
/// publish, dropping the node's own echo.
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
    /// Changes retained for slow subscribers before they receive `Resync`.
    pub fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    /// Node identifier. Default: random.
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
                expiries: Mutex::new(Expiries::default()),
                sessions: AtomicU64::new(UNRELEASED),
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

pub(crate) fn now_ms() -> u64 {
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
    /// Local-only hub, with no transport.
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

    /// Stamps origin, sequence and time, delivers locally and publishes on the transport. Local
    /// delivery happens even if the transport fails; the error goes back to whoever published.
    pub async fn publish(&self, mut change: Change) -> Result<Change, TransportError> {
        self.stamp(&mut change);
        self.deliver(&change);
        if let Some(transport) = &self.inner.transport {
            transport.publish(&change).await?;
        }
        Ok(change)
    }

    fn stamp(&self, change: &mut Change) {
        change.origin = self.inner.origin.clone();
        change.seq = self.inner.seq.fetch_add(1, Ordering::Relaxed) + 1;
        if change.at == 0 {
            change.at = now_ms();
        }
    }

    /// Delivers `change` on this node when the clock reaches `boundary_ms` (milliseconds since the
    /// Unix epoch), so sessions affected by a grant or role that starts or stops being in force
    /// recompute without anyone publishing. `now_ms` is the caller's current instant; the wait is
    /// `boundary_ms - now_ms`, at least 1 ms.
    ///
    /// Every instance schedules its own notice, so it is delivered locally and never goes through the
    /// transport. Scheduling the same boundary and subject again is a no-op. Pending notices are
    /// cancelled when the last clone of the hub is dropped. If the same boundary keeps being
    /// scheduled right after it fires (a clock that does not move), the repeats back off up to 5 s.
    /// Returns `false`, scheduling nothing, when called outside a Tokio runtime.
    ///
    /// A notice scheduled here stays until it fires; sessions use an internal variant that cancels it
    /// when the last session that asked for it closes.
    pub fn schedule_expiry(&self, boundary_ms: u64, now_ms: u64, change: Change) -> bool {
        self.schedule(UNRELEASED, boundary_ms, now_ms, change)
    }

    pub(crate) fn new_session_id(&self) -> u64 {
        self.inner.sessions.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn schedule_for_session(&self, session: u64, boundary_ms: u64, now_ms: u64, change: Change) -> bool {
        self.schedule(session, boundary_ms, now_ms, change)
    }

    /// Drops `session` from every pending notice and cancels the ones nobody else wants.
    pub(crate) fn release_session(&self, session: u64) {
        let mut expiries = self.lock_expiries();
        expiries.pending.retain(|_, pending| {
            pending.holders.remove(&session);
            let wanted = !pending.holders.is_empty();
            if !wanted {
                pending.task.abort();
            }
            wanted
        });
    }

    #[cfg(test)]
    pub(crate) fn pending_expiries(&self) -> usize {
        self.lock_expiries().pending.len()
    }

    fn lock_expiries(&self) -> std::sync::MutexGuard<'_, Expiries> {
        self.inner
            .expiries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn schedule(&self, holder: u64, boundary_ms: u64, now_ms: u64, change: Change) -> bool {
        if tokio::runtime::Handle::try_current().is_err() {
            return false;
        }
        let key = (boundary_ms, change.subject.clone());
        let mut expiries = self.lock_expiries();
        // A finished handle under the key means its runtime went away before the notice fired.
        if let Some(pending) = expiries.pending.get_mut(&key)
            && !pending.task.is_finished()
        {
            pending.holders.insert(holder);
            return true;
        }
        let mut wait = Duration::from_millis(boundary_ms.saturating_sub(now_ms).max(1));
        if let Some(&(at, repeats)) = expiries.fired.get(&key)
            && at.elapsed() < REPEAT_WINDOW
            && repeats >= FREE_REPEATS
        {
            let backoff = REPEAT_BACKOFF
                .saturating_mul(1 << (repeats - FREE_REPEATS).min(16))
                .min(MAX_REPEAT_BACKOFF);
            wait = wait.max(backoff);
        }
        let inner = Arc::downgrade(&self.inner);
        let task_key = key.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            fire_expiry(inner, task_key, change);
        });
        let pending = PendingExpiry {
            task,
            holders: HashSet::from([holder]),
        };
        expiries.pending.insert(key, pending);
        true
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

    /// Delivers a change on this node only, without the transport.
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

    /// Listens to the transport in the background and delivers here what the other instances
    /// publish. Reconnects with exponential backoff (100 ms up to 5 s) and emits `Resync` on every
    /// reconnection, because whatever was published in the gap is lost. With no transport, it does
    /// nothing. The relay stops when the [`RelayHandle`] is dropped.
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

fn fire_expiry(inner: Weak<Inner>, key: ExpiryKey, mut change: Change) {
    let Some(inner) = inner.upgrade() else {
        return;
    };
    let hub = Hub { inner };
    // Forget the key before delivering, so the session that reacts can schedule the next boundary.
    {
        let mut expiries = hub.lock_expiries();
        expiries.pending.remove(&key);
        let now = Instant::now();
        expiries
            .fired
            .retain(|_, (at, _)| now.duration_since(*at) < REPEAT_WINDOW);
        let repeats = expiries.fired.get(&key).map_or(1, |(_, n)| n.saturating_add(1));
        expiries.fired.insert(key, (now, repeats));
    }
    hub.stamp(&mut change);
    hub.deliver(&change);
}

/// Keeps the relay alive; drop it to stop.
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

    #[tokio::test(start_paused = true)]
    async fn expiry_is_delivered_once_at_the_boundary() {
        let hub = Hub::new();
        let mut rx = hub.subscribe();
        assert!(hub.schedule_expiry(1_500, 1_000, Change::expiry_for_everyone()));
        assert!(hub.schedule_expiry(1_500, 1_000, Change::expiry_for_everyone()));

        tokio::time::sleep(Duration::from_millis(499)).await;
        assert!(rx.try_recv().is_err(), "nothing before the boundary");
        tokio::time::sleep(Duration::from_millis(2)).await;
        let change = rx.try_recv().expect("notice at the boundary");
        assert_eq!(change.kind, ChangeKind::Grants);
        assert_eq!(change.origin, hub.origin());
        assert!(rx.try_recv().is_err(), "the same boundary is scheduled once");
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_hub_cancels_pending_expiries() {
        let hub = Hub::new();
        let mut rx = hub.subscribe();
        hub.schedule_expiry(2_000, 1_000, Change::expiry_for_everyone());
        drop(hub);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(matches!(rx.try_recv(), Err(broadcast::error::TryRecvError::Closed)));
    }

    #[test]
    fn expiry_outside_a_runtime_schedules_nothing() {
        assert!(!Hub::new().schedule_expiry(2_000, 1_000, Change::expiry_for_everyone()));
    }

    #[tokio::test(start_paused = true)]
    async fn a_boundary_already_passed_fires_at_once() {
        let hub = Hub::new();
        let mut rx = hub.subscribe();
        assert!(hub.schedule_expiry(500, 1_000, Change::expiry_for_everyone()));
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn each_subject_gets_its_own_notice_and_it_keeps_the_subject() {
        let hub = Hub::new();
        let mut rx = hub.subscribe();
        hub.schedule_expiry(1_100, 1_000, Change::expiry("alice"));
        hub.schedule_expiry(1_100, 1_000, Change::expiry("bob"));
        tokio::time::sleep(Duration::from_millis(101)).await;
        let mut subjects = vec![
            rx.try_recv().unwrap().subject.unwrap(),
            rx.try_recv().unwrap().subject.unwrap(),
        ];
        subjects.sort();
        assert_eq!(subjects, ["alice", "bob"]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_same_boundary_can_be_scheduled_again_after_it_fired() {
        let hub = Hub::new();
        let mut rx = hub.subscribe();
        hub.schedule_expiry(1_100, 1_000, Change::expiry_for_everyone());
        tokio::time::sleep(Duration::from_millis(101)).await;
        assert!(rx.try_recv().is_ok());
        hub.schedule_expiry(1_100, 1_000, Change::expiry_for_everyone());
        tokio::time::sleep(Duration::from_millis(101)).await;
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn releasing_the_last_session_cancels_the_notice() {
        let hub = Hub::new();
        let mut rx = hub.subscribe();
        let (a, b) = (hub.new_session_id(), hub.new_session_id());
        hub.schedule_for_session(a, 2_000, 1_000, Change::expiry("alice"));
        hub.schedule_for_session(b, 2_000, 1_000, Change::expiry("alice"));
        hub.schedule_for_session(a, 3_000, 1_000, Change::expiry("alice"));
        assert_eq!(hub.pending_expiries(), 2);

        hub.release_session(a);
        assert_eq!(hub.pending_expiries(), 1, "the notice b still wants stays");
        hub.release_session(b);
        assert_eq!(hub.pending_expiries(), 0);

        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(rx.try_recv().is_err(), "a cancelled notice fired");
    }

    #[tokio::test(start_paused = true)]
    async fn a_notice_scheduled_through_the_public_api_survives_session_release() {
        let hub = Hub::new();
        let session = hub.new_session_id();
        hub.schedule_expiry(2_000, 1_000, Change::expiry("alice"));
        hub.schedule_for_session(session, 2_000, 1_000, Change::expiry("alice"));
        hub.release_session(session);
        assert_eq!(hub.pending_expiries(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_boundary_scheduled_again_as_soon_as_it_fires_backs_off() {
        // A clock stuck one millisecond before the boundary: every reaction schedules it again.
        let hub = Hub::new();
        let mut rx = hub.subscribe();
        let mut delivered = 0u32;
        hub.schedule_expiry(1_000, 999, Change::expiry("alice"));
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            tokio::select! {
                _ = rx.recv() => {
                    delivered += 1;
                    hub.schedule_expiry(1_000, 999, Change::expiry("alice"));
                }
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }
        assert!(delivered <= 8, "{delivered} notices in 2 s: the loop spins");
        assert!(delivered >= 3, "backoff must not stop the notices");
    }
}
