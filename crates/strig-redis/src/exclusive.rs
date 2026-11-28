//! Exclusive leases in Redis.

use std::sync::Mutex;
use std::time::Duration;

use redis::{Client, Connection, Value};
use strig::ObjectRef;
use strig::exclusive::{Acquisition, Claim, ExclusiveStore, Lease, OwnedChange, Preemption, StoreError};

/// Optimistic attempts of one operation before it gives up and fails closed.
const ATTEMPTS: usize = 64;

fn store_error(error: impl std::fmt::Display) -> StoreError {
    StoreError(error.to_string())
}

enum Write {
    Keep,
    Set(Lease),
    Delete,
}

/// [`ExclusiveStore`] over Redis, for a resource held across processes.
///
/// Every decision is a `WATCH`/`MULTI`/`EXEC` transaction on the key of the resource: it reads the
/// lease, decides with the same rule as the in-memory store ([`Acquisition::decide`],
/// [`OwnedChange::decide`], in Rust, so priorities keep all 64 bits) and writes only if no one else
/// touched the key meanwhile, otherwise it reads again. After 64 lost races it fails closed with a
/// [`StoreError`]. Each process that shares a resource must use the same prefix.
///
/// Whether a lease is active is decided with the instant the caller passes, as in the core, never with
/// the clock of Redis. The native expiry is only the garbage collector: a key lives for the lease's
/// lifetime plus a retention (one hour by default, [`RedisExclusiveStore::with_retention`]), so a lease
/// that ran out by the caller's clock is still there for [`strig::exclusive::ExclusiveRegistry::expire`]
/// to report, and Redis reclaims it on its own if no one ever sweeps.
///
/// Unlike [`strig_postgres::PgExclusiveStore`](https://docs.rs/strig-postgres) there is no worker
/// thread: the trait is synchronous and the `redis` crate has a synchronous connection with connect,
/// read and write timeouts, so a call blocks the caller for the round trip (inside an async task use
/// `tokio::task::spawn_blocking`) and a call that times out is a [`StoreError`] that refuses the claim.
/// The write of a timed-out call may still have reached Redis, which at worst leaves a lease its
/// claimant does not know about until it runs out. One connection is shared by the calls of a store
/// behind a lock and is reopened after any error.
///
/// Keys are `{<prefix>}:lease:<len(kind)>:<kind>:<id>` and the set `{<prefix>}:index`; the braces keep
/// them in one hash slot on a cluster.
pub struct RedisExclusiveStore {
    client: Client,
    prefix: String,
    timeout: Duration,
    retention: Duration,
    connection: Mutex<Option<Connection>>,
}

impl RedisExclusiveStore {
    /// # Errors
    ///
    /// [`StoreError`] when the url does not parse or the prefix is empty. It does not connect yet.
    pub fn new(url: &str, prefix: impl Into<String>) -> Result<Self, StoreError> {
        Self::from_client(Client::open(url).map_err(store_error)?, prefix)
    }

    /// # Errors
    ///
    /// [`StoreError`] when the prefix is empty or contains a brace.
    pub fn from_client(client: Client, prefix: impl Into<String>) -> Result<Self, StoreError> {
        let prefix = prefix.into();
        if prefix.is_empty() || prefix.contains(['{', '}']) {
            return Err(store_error("the prefix must be non-empty and have no braces"));
        }
        Ok(Self {
            client,
            prefix,
            timeout: Duration::from_secs(5),
            retention: Duration::from_secs(3600),
            connection: Mutex::new(None),
        })
    }

    /// How long connecting, writing and reading may take before the call fails closed. Default 5 seconds.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How long a lease that ran out stays in Redis for the sweep to find. Default one hour.
    #[must_use]
    pub fn with_retention(mut self, retention: Duration) -> Self {
        self.retention = retention;
        self
    }

    fn key(&self, resource: &ObjectRef) -> String {
        format!(
            "{{{}}}:lease:{}:{}:{}",
            self.prefix,
            resource.kind.len(),
            resource.kind,
            resource.id
        )
    }

    fn index(&self) -> String {
        format!("{{{}}}:index", self.prefix)
    }

    fn lifetime_ms(&self, lease: &Lease) -> u64 {
        let span = lease.expires_at.saturating_sub(lease.acquired_at);
        let retention = u64::try_from(self.retention.as_millis()).unwrap_or(u64::MAX);
        span.saturating_add(retention).clamp(1, i64::MAX as u64)
    }

    fn with_connection<T>(&self, f: impl FnOnce(&mut Connection) -> Result<T, StoreError>) -> Result<T, StoreError> {
        let mut guard = self
            .connection
            .lock()
            .map_err(|_| store_error("the connection lock is poisoned"))?;
        let mut connection = match guard.take() {
            Some(connection) => connection,
            None => {
                let connection = self
                    .client
                    .get_connection_with_timeout(self.timeout)
                    .map_err(store_error)?;
                connection.set_read_timeout(Some(self.timeout)).map_err(store_error)?;
                connection.set_write_timeout(Some(self.timeout)).map_err(store_error)?;
                connection
            }
        };
        let result = f(&mut connection);
        if result.is_ok() {
            *guard = Some(connection);
        }
        result
    }

    fn read(connection: &mut Connection, key: &str) -> Result<Option<Lease>, StoreError> {
        let text: Option<String> = redis::cmd("GET").arg(key).query(connection).map_err(store_error)?;
        text.map(|text| serde_json::from_str(&text).map_err(store_error))
            .transpose()
    }

    /// Reads the lease of `resource` under a `WATCH`, lets `decide` choose, and applies its write only
    /// if the key did not change; otherwise starts again.
    fn transact<T>(
        &self,
        resource: &ObjectRef,
        mut decide: impl FnMut(Option<Lease>) -> Result<(T, Write), StoreError>,
    ) -> Result<T, StoreError> {
        let (key, index) = (self.key(resource), self.index());
        self.with_connection(|connection| {
            for _ in 0..ATTEMPTS {
                redis::cmd("WATCH")
                    .arg(&key)
                    .query::<()>(connection)
                    .map_err(store_error)?;
                let current = Self::read(connection, &key)?;
                let (outcome, write) = decide(current)?;
                let mut pipe = redis::pipe();
                pipe.atomic();
                match write {
                    Write::Keep => {
                        redis::cmd("UNWATCH").query::<()>(connection).map_err(store_error)?;
                        return Ok(outcome);
                    }
                    Write::Set(lease) => {
                        let json = serde_json::to_string(&lease).map_err(store_error)?;
                        pipe.cmd("SET")
                            .arg(&key)
                            .arg(json)
                            .arg("PX")
                            .arg(self.lifetime_ms(&lease));
                        pipe.cmd("SADD").arg(&index).arg(&key);
                    }
                    Write::Delete => {
                        pipe.cmd("DEL").arg(&key);
                        pipe.cmd("SREM").arg(&index).arg(&key);
                    }
                }
                let done: Option<Vec<Value>> = pipe.query(connection).map_err(store_error)?;
                if done.is_some() {
                    return Ok(outcome);
                }
            }
            Err(store_error("the lease kept changing under the transaction"))
        })
    }
}

impl ExclusiveStore for RedisExclusiveStore {
    fn get(&self, resource: &ObjectRef) -> Result<Option<Lease>, StoreError> {
        let key = self.key(resource);
        self.with_connection(|connection| Self::read(connection, &key))
    }

    fn put(&mut self, lease: Lease) -> Result<(), StoreError> {
        let resource = lease.resource.clone();
        self.transact(&resource, |_| Ok(((), Write::Set(lease.clone()))))
    }

    fn remove(&mut self, resource: &ObjectRef) -> Result<Option<Lease>, StoreError> {
        self.transact(resource, |current| {
            let write = if current.is_some() { Write::Delete } else { Write::Keep };
            Ok((current, write))
        })
    }

    fn leases(&self) -> Result<Vec<Lease>, StoreError> {
        let index = self.index();
        let mut leases = self.with_connection(|connection| {
            let keys: Vec<String> = redis::cmd("SMEMBERS")
                .arg(&index)
                .query(connection)
                .map_err(store_error)?;
            let mut leases = Vec::new();
            for key in keys {
                if let Some(lease) = Self::read(connection, &key)? {
                    leases.push(lease);
                }
            }
            Ok(leases)
        })?;
        leases.sort_by(|a, b| a.resource.cmp(&b.resource));
        Ok(leases)
    }

    fn acquire_lease(&mut self, claim: &Claim, now: u64, preemption: Preemption) -> Result<Acquisition, StoreError> {
        self.transact(&claim.resource, |current| {
            let outcome = Acquisition::decide(current, claim, now, preemption);
            let write = if matches!(outcome, Acquisition::Busy { .. }) {
                Write::Keep
            } else {
                Write::Set(Lease::granted(claim, now))
            };
            Ok((outcome, write))
        })
    }

    fn renew_lease(
        &mut self,
        resource: &ObjectRef,
        holder: &ObjectRef,
        now: u64,
        ttl_ms: u64,
    ) -> Result<OwnedChange, StoreError> {
        self.transact(resource, |current| match OwnedChange::decide(current, holder, now) {
            OwnedChange::Applied(lease) => {
                let renewed = lease.renewed(now, ttl_ms);
                Ok((OwnedChange::Applied(renewed.clone()), Write::Set(renewed)))
            }
            other => Ok((other, Write::Keep)),
        })
    }

    fn release_lease(&mut self, resource: &ObjectRef, holder: &ObjectRef, now: u64) -> Result<OwnedChange, StoreError> {
        self.transact(resource, |current| {
            let change = OwnedChange::decide(current, holder, now);
            let write = if matches!(change, OwnedChange::Applied(_)) {
                Write::Delete
            } else {
                Write::Keep
            };
            Ok((change, write))
        })
    }

    fn remove_expired(&mut self, now: u64) -> Result<Vec<Lease>, StoreError> {
        let mut removed = Vec::new();
        for lease in self.leases()? {
            if lease.is_active(now) {
                continue;
            }
            let gone = self.transact(&lease.resource, |current| match current {
                Some(current) if !current.is_active(now) => Ok((Some(current), Write::Delete)),
                _ => Ok((None, Write::Keep)),
            })?;
            removed.extend(gone);
        }
        removed.sort_by(|a, b| a.resource.cmp(&b.resource));
        Ok(removed)
    }
}
