//! Exclusive leases in Postgres.

use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use strig::ObjectRef;
use strig::exclusive::{Acquisition, Claim, ExclusiveStore, Lease, OwnedChange, Preemption, StoreError};
use tokio::sync::{mpsc, oneshot};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::{Client, Config, GenericClient, NoTls, Row, Socket};

use crate::query::{PgQueryError, PgTables};

fn store_error(error: impl std::fmt::Display) -> StoreError {
    StoreError(error.to_string())
}

fn instant(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| store_error("instant does not fit a bigint column"))
}

fn from_instant(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| store_error("negative instant in the lease table"))
}

const COLUMNS: &str = "resource_kind, resource_id, holder_kind, holder_id, priority, acquired_at, expires_at";

fn lease_of(row: &Row) -> Result<Lease, StoreError> {
    Ok(Lease {
        resource: ObjectRef::new(row.get::<_, String>(0), row.get::<_, String>(1)),
        holder: ObjectRef::new(row.get::<_, String>(2), row.get::<_, String>(3)),
        priority: row.get(4),
        acquired_at: from_instant(row.get(5))?,
        expires_at: from_instant(row.get(6))?,
    })
}

impl PgTables {
    async fn select_lease_for_update<C: GenericClient>(
        &self,
        client: &C,
        resource: &ObjectRef,
    ) -> Result<Option<Lease>, StoreError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM {} WHERE resource_kind = $1 AND resource_id = $2 FOR UPDATE",
            self.qualified(&self.exclusive)
        );
        let row = client
            .query_opt(&sql, &[&resource.kind, &resource.id])
            .await
            .map_err(store_error)?;
        row.as_ref().map(lease_of).transpose()
    }

    async fn write_lease<C: GenericClient>(&self, client: &C, lease: &Lease) -> Result<(), StoreError> {
        let sql = format!(
            "UPDATE {} SET holder_kind = $3, holder_id = $4, priority = $5, acquired_at = $6, expires_at = $7 \
             WHERE resource_kind = $1 AND resource_id = $2",
            self.qualified(&self.exclusive)
        );
        client
            .execute(
                &sql,
                &[
                    &lease.resource.kind,
                    &lease.resource.id,
                    &lease.holder.kind,
                    &lease.holder.id,
                    &lease.priority,
                    &instant(lease.acquired_at)?,
                    &instant(lease.expires_at)?,
                ],
            )
            .await
            .map_err(store_error)?;
        Ok(())
    }

    /// Inserts the lease unless the resource has a row; true when it was inserted.
    async fn insert_lease<C: GenericClient>(&self, client: &C, lease: &Lease) -> Result<bool, StoreError> {
        let sql = format!(
            "INSERT INTO {} ({COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (resource_kind, resource_id) DO NOTHING",
            self.qualified(&self.exclusive)
        );
        let inserted = client
            .execute(
                &sql,
                &[
                    &lease.resource.kind,
                    &lease.resource.id,
                    &lease.holder.kind,
                    &lease.holder.id,
                    &lease.priority,
                    &instant(lease.acquired_at)?,
                    &instant(lease.expires_at)?,
                ],
            )
            .await
            .map_err(store_error)?;
        Ok(inserted > 0)
    }

    /// Locks the row of the resource, creating it from `fresh` when there is none. Returns the lease
    /// that was there (`None` when `fresh` was just inserted).
    async fn lock_or_insert<C: GenericClient>(&self, client: &C, fresh: &Lease) -> Result<Option<Lease>, StoreError> {
        loop {
            if let Some(current) = self.select_lease_for_update(client, &fresh.resource).await? {
                return Ok(Some(current));
            }
            if self.insert_lease(client, fresh).await? {
                return Ok(None);
            }
        }
    }

    pub(crate) async fn exclusive_acquire(
        &self,
        client: &mut Client,
        claim: &Claim,
        now: u64,
        preemption: Preemption,
    ) -> Result<Acquisition, StoreError> {
        let fresh = Lease::granted(claim, now);
        instant(fresh.expires_at)?;
        let tx = client.transaction().await.map_err(store_error)?;
        let Some(current) = self.lock_or_insert(&tx, &fresh).await? else {
            tx.commit().await.map_err(store_error)?;
            return Ok(Acquisition::Granted);
        };
        let outcome = Acquisition::decide(Some(current), claim, now, preemption);
        if !matches!(outcome, Acquisition::Busy { .. }) {
            self.write_lease(&tx, &fresh).await?;
        }
        tx.commit().await.map_err(store_error)?;
        Ok(outcome)
    }

    pub(crate) async fn exclusive_renew(
        &self,
        client: &mut Client,
        resource: &ObjectRef,
        holder: &ObjectRef,
        now: u64,
        ttl_ms: u64,
    ) -> Result<OwnedChange, StoreError> {
        instant(now.saturating_add(ttl_ms))?;
        let tx = client.transaction().await.map_err(store_error)?;
        let current = self.select_lease_for_update(&tx, resource).await?;
        let change = OwnedChange::decide(current, holder, now);
        let result = if let OwnedChange::Applied(lease) = change {
            let renewed = lease.renewed(now, ttl_ms);
            self.write_lease(&tx, &renewed).await?;
            OwnedChange::Applied(renewed)
        } else {
            change
        };
        tx.commit().await.map_err(store_error)?;
        Ok(result)
    }

    pub(crate) async fn exclusive_release(
        &self,
        client: &mut Client,
        resource: &ObjectRef,
        holder: &ObjectRef,
        now: u64,
    ) -> Result<OwnedChange, StoreError> {
        let tx = client.transaction().await.map_err(store_error)?;
        let current = self.select_lease_for_update(&tx, resource).await?;
        let change = OwnedChange::decide(current, holder, now);
        if matches!(change, OwnedChange::Applied(_)) {
            self.delete_lease(&tx, resource).await?;
        }
        tx.commit().await.map_err(store_error)?;
        Ok(change)
    }

    async fn delete_lease<C: GenericClient>(
        &self,
        client: &C,
        resource: &ObjectRef,
    ) -> Result<Option<Lease>, StoreError> {
        let sql = format!(
            "DELETE FROM {} WHERE resource_kind = $1 AND resource_id = $2 RETURNING {COLUMNS}",
            self.qualified(&self.exclusive)
        );
        let row = client
            .query_opt(&sql, &[&resource.kind, &resource.id])
            .await
            .map_err(store_error)?;
        row.as_ref().map(lease_of).transpose()
    }

    async fn exclusive_get<C: GenericClient>(
        &self,
        client: &C,
        resource: &ObjectRef,
    ) -> Result<Option<Lease>, StoreError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM {} WHERE resource_kind = $1 AND resource_id = $2",
            self.qualified(&self.exclusive)
        );
        let row = client
            .query_opt(&sql, &[&resource.kind, &resource.id])
            .await
            .map_err(store_error)?;
        row.as_ref().map(lease_of).transpose()
    }

    async fn exclusive_leases<C: GenericClient>(&self, client: &C) -> Result<Vec<Lease>, StoreError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM {} ORDER BY resource_kind COLLATE \"C\", resource_id COLLATE \"C\"",
            self.qualified(&self.exclusive)
        );
        let rows = client.query(&sql, &[]).await.map_err(store_error)?;
        rows.iter().map(lease_of).collect()
    }

    async fn exclusive_remove_expired<C: GenericClient>(&self, client: &C, now: u64) -> Result<Vec<Lease>, StoreError> {
        let sql = format!(
            "DELETE FROM {} WHERE expires_at <= $1 RETURNING {COLUMNS}",
            self.qualified(&self.exclusive)
        );
        let rows = client.query(&sql, &[&instant(now)?]).await.map_err(store_error)?;
        let mut leases = rows.iter().map(lease_of).collect::<Result<Vec<_>, _>>()?;
        leases.sort_by(|a, b| a.resource.cmp(&b.resource));
        Ok(leases)
    }

    async fn exclusive_put(&self, client: &mut Client, lease: &Lease) -> Result<(), StoreError> {
        instant(lease.acquired_at)?;
        instant(lease.expires_at)?;
        let tx = client.transaction().await.map_err(store_error)?;
        if self.lock_or_insert(&tx, lease).await?.is_some() {
            self.write_lease(&tx, lease).await?;
        }
        tx.commit().await.map_err(store_error)
    }
}

enum Op {
    Get(ObjectRef),
    Put(Lease),
    Remove(ObjectRef),
    Leases,
    Acquire(Claim, u64, Preemption),
    Renew(ObjectRef, ObjectRef, u64, u64),
    Release(ObjectRef, ObjectRef, u64),
    RemoveExpired(u64),
}

enum Reply {
    Done,
    Lease(Box<Option<Lease>>),
    Leases(Vec<Lease>),
    Acquisition(Acquisition),
    Change(OwnedChange),
}

type Job = (Op, std_mpsc::Sender<Result<Reply, StoreError>>);

async fn run(tables: &PgTables, client: &mut Client, op: Op) -> Result<Reply, StoreError> {
    match op {
        Op::Get(resource) => tables
            .exclusive_get(client, &resource)
            .await
            .map(|lease| Reply::Lease(Box::new(lease))),
        Op::Put(lease) => tables.exclusive_put(client, &lease).await.map(|()| Reply::Done),
        Op::Remove(resource) => tables
            .delete_lease(client, &resource)
            .await
            .map(|lease| Reply::Lease(Box::new(lease))),
        Op::Leases => tables.exclusive_leases(client).await.map(Reply::Leases),
        Op::Acquire(claim, now, preemption) => tables
            .exclusive_acquire(client, &claim, now, preemption)
            .await
            .map(Reply::Acquisition),
        Op::Renew(resource, holder, now, ttl) => tables
            .exclusive_renew(client, &resource, &holder, now, ttl)
            .await
            .map(Reply::Change),
        Op::Release(resource, holder, now) => tables
            .exclusive_release(client, &resource, &holder, now)
            .await
            .map(Reply::Change),
        Op::RemoveExpired(now) => tables.exclusive_remove_expired(client, now).await.map(Reply::Leases),
    }
}

/// [`ExclusiveStore`] over a Postgres table, for a resource held across processes.
///
/// Every decision (`acquire_lease`, `renew_lease`, `release_lease`, `remove_expired`) is one
/// transaction that locks the row of the resource, so two instances racing for it are serialised by
/// the database and exactly one wins. Expiry is decided with the instant the caller passes, never with
/// the clock of the database. As in [`PgPendingStore`](crate::PgPendingStore), the trait is
/// synchronous, so the store owns one connection on a thread of its own and a call blocks the caller
/// for the round trip (inside an async task use [`tokio::task::spawn_blocking`]). A call that does not
/// answer within the timeout is a [`StoreError`], so the claim is refused; the transaction may still
/// commit afterwards, which at worst leaves a lease its claimant does not know about until it runs
/// out. A dropped connection is reopened on the next call.
pub struct PgExclusiveStore {
    jobs: mpsc::UnboundedSender<Job>,
    timeout: Duration,
}

impl PgExclusiveStore {
    /// Connects without TLS. See [`PgExclusiveStore::connect_with_tls`].
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] when the first connection fails.
    pub async fn connect(url: &str, tables: PgTables) -> Result<Self, PgQueryError> {
        Self::connect_with_tls(url, tables, NoTls).await
    }

    /// Connects with the given TLS connector and starts the worker thread. The schema must already be
    /// at version 4 ([`crate::migrate_with`]).
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] when the first connection fails (or the url does not parse).
    pub async fn connect_with_tls<T>(url: &str, tables: PgTables, tls: T) -> Result<Self, PgQueryError>
    where
        T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
        T::Stream: Send + 'static,
        T::TlsConnect: Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let config: Config = url.parse()?;
        let (jobs, mut queue) = mpsc::unbounded_channel::<Job>();
        let (ready, started) = oneshot::channel::<Result<(), tokio_postgres::Error>>();
        std::thread::Builder::new()
            .name("strig-pg-exclusive".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
                let Ok(runtime) = runtime else { return };
                runtime.block_on(async move {
                    let open = || async {
                        let (client, connection) = config.connect(tls.clone()).await?;
                        tokio::spawn(connection);
                        Ok::<Client, tokio_postgres::Error>(client)
                    };
                    let mut client = match open().await {
                        Ok(client) => {
                            let _ = ready.send(Ok(()));
                            Some(client)
                        }
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    };
                    while let Some((op, reply)) = queue.recv().await {
                        if client.as_ref().is_none_or(Client::is_closed) {
                            client = open().await.ok();
                        }
                        let result = match client.as_mut() {
                            Some(client) => run(&tables, client, op).await,
                            None => Err(store_error("no connection to the database")),
                        };
                        let _ = reply.send(result);
                    }
                });
            })
            .map_err(|error| PgQueryError::Invalid(error.to_string()))?;
        match started.await {
            Ok(Ok(())) => Ok(Self {
                jobs,
                timeout: Duration::from_secs(10),
            }),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(PgQueryError::Invalid("the worker thread did not start".into())),
        }
    }

    /// How long a call waits for the database before it fails closed. Default 10 seconds.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn call(&self, op: Op) -> Result<Reply, StoreError> {
        let (reply, answer) = std_mpsc::channel();
        self.jobs
            .send((op, reply))
            .map_err(|_| store_error("the store worker stopped"))?;
        answer
            .recv_timeout(self.timeout)
            .map_err(|_| store_error("the database did not answer in time"))?
    }

    fn lease(&self, op: Op) -> Result<Option<Lease>, StoreError> {
        match self.call(op)? {
            Reply::Lease(lease) => Ok(*lease),
            _ => Err(store_error("unexpected reply")),
        }
    }

    fn leases_of(&self, op: Op) -> Result<Vec<Lease>, StoreError> {
        match self.call(op)? {
            Reply::Leases(leases) => Ok(leases),
            _ => Err(store_error("unexpected reply")),
        }
    }

    fn change(&self, op: Op) -> Result<OwnedChange, StoreError> {
        match self.call(op)? {
            Reply::Change(change) => Ok(change),
            _ => Err(store_error("unexpected reply")),
        }
    }
}

impl ExclusiveStore for PgExclusiveStore {
    fn get(&self, resource: &ObjectRef) -> Result<Option<Lease>, StoreError> {
        self.lease(Op::Get(resource.clone()))
    }

    fn put(&mut self, lease: Lease) -> Result<(), StoreError> {
        self.call(Op::Put(lease)).map(|_| ())
    }

    fn remove(&mut self, resource: &ObjectRef) -> Result<Option<Lease>, StoreError> {
        self.lease(Op::Remove(resource.clone()))
    }

    fn leases(&self) -> Result<Vec<Lease>, StoreError> {
        self.leases_of(Op::Leases)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "strig.postgres.exclusive.acquire", level = "info", skip_all)
    )]
    fn acquire_lease(&mut self, claim: &Claim, now: u64, preemption: Preemption) -> Result<Acquisition, StoreError> {
        match self.call(Op::Acquire(claim.clone(), now, preemption))? {
            Reply::Acquisition(outcome) => Ok(outcome),
            _ => Err(store_error("unexpected reply")),
        }
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "strig.postgres.exclusive.renew", level = "info", skip_all)
    )]
    fn renew_lease(
        &mut self,
        resource: &ObjectRef,
        holder: &ObjectRef,
        now: u64,
        ttl_ms: u64,
    ) -> Result<OwnedChange, StoreError> {
        self.change(Op::Renew(resource.clone(), holder.clone(), now, ttl_ms))
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "strig.postgres.exclusive.release", level = "info", skip_all)
    )]
    fn release_lease(&mut self, resource: &ObjectRef, holder: &ObjectRef, now: u64) -> Result<OwnedChange, StoreError> {
        self.change(Op::Release(resource.clone(), holder.clone(), now))
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "strig.postgres.exclusive.remove_expired", level = "info", skip_all)
    )]
    fn remove_expired(&mut self, now: u64) -> Result<Vec<Lease>, StoreError> {
        self.leases_of(Op::RemoveExpired(now))
    }
}
