//! In-memory snapshots of the grants and the tuples, loaded from Postgres.
//!
//! The core does no IO: [`GrantSource`] and [`TupleStore`] are synchronous. [`PgStore`] keeps a
//! snapshot of each table in memory, serves the engine from it, and reloads it when the transport
//! delivers a [`Change`]. A store only exists loaded: [`PgStore::load`] reads the tables before it
//! returns, so the engine never decides over an empty set that would be missing a deny.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use strig::{Grant, GrantIndex, GrantSource, ObjectRef, Resource, Subject, SubjectMatcher, Tuple, TupleIndex};
use strig::{TupleStore, TupleSubject};
use strig_sync::{Change, ChangeKind};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::task::JoinHandle;
use tokio_postgres::{Client, GenericClient, NoTls};

use crate::query::{PgQueryError, PgTables};

#[derive(Default)]
struct TupleSnapshot {
    subjects: HashMap<(ObjectRef, String), Vec<TupleSubject>>,
    objects: HashMap<String, Vec<ObjectRef>>,
    written: HashMap<ObjectRef, Vec<(String, TupleSubject)>>,
}

impl TupleSnapshot {
    fn build(tuples: Vec<Tuple>) -> Self {
        let mut snapshot = Self::default();
        for tuple in tuples {
            let objects = snapshot.objects.entry(tuple.object.kind.clone()).or_default();
            if objects.last() != Some(&tuple.object) {
                objects.push(tuple.object.clone());
            }
            snapshot
                .written
                .entry(tuple.object.clone())
                .or_default()
                .push((tuple.relation.clone(), tuple.subject.clone()));
            snapshot
                .subjects
                .entry((tuple.object, tuple.relation))
                .or_default()
                .push(tuple.subject);
        }
        snapshot
    }
}

struct Shared {
    grants: RwLock<Arc<Vec<Grant>>>,
    tuples: RwLock<Arc<TupleSnapshot>>,
    stale: AtomicBool,
}

fn read<T: Clone>(slot: &RwLock<T>) -> T {
    slot.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

fn replace<T>(slot: &RwLock<T>, value: T) {
    *slot.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
}

/// What a notice makes the store reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reload {
    Grants,
    Tuples,
    Both,
}

impl Reload {
    fn for_change(change: &Change) -> Option<Self> {
        match change.kind {
            ChangeKind::Grants => Some(Self::Grants),
            ChangeKind::Tuples => Some(Self::Tuples),
            ChangeKind::Resync => Some(Self::Both),
            _ => None,
        }
    }
}

/// The grants and the tuples of the tables, held in memory.
///
/// [`PgStore::grants`] and [`PgStore::tuples`] hand out the handles the engine reads; they share the
/// snapshot, so a reload is seen by every handle at once.
///
/// A reload that fails keeps the previous snapshot and marks the store [stale](PgStore::is_stale):
/// the engine keeps deciding over the last set it knew, so wire `is_stale` to the readiness probe of
/// the service and drain the instance if it stays so.
#[derive(Clone)]
pub struct PgStore {
    tables: PgTables,
    shared: Arc<Shared>,
}

impl PgStore {
    /// Reads both tables and returns the store.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] or [`PgQueryError::Decode`] when a table cannot be read.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "strig.postgres.store.load", level = "info", skip_all)
    )]
    pub async fn load<C: GenericClient>(client: &C, tables: PgTables) -> Result<Self, PgQueryError> {
        let grants = tables.all_grants(client).await?;
        let tuples = tables.all_tuples(client).await?;
        Ok(Self {
            tables,
            shared: Arc::new(Shared {
                grants: RwLock::new(Arc::new(grants)),
                tuples: RwLock::new(Arc::new(TupleSnapshot::build(tuples))),
                stale: AtomicBool::new(false),
            }),
        })
    }

    pub fn tables(&self) -> &PgTables {
        &self.tables
    }

    /// The [`GrantSource`] and [`GrantIndex`] over the snapshot.
    pub fn grants(&self) -> PgGrants {
        PgGrants {
            shared: self.shared.clone(),
        }
    }

    /// The [`TupleStore`] and [`TupleIndex`] over the snapshot.
    pub fn tuples(&self) -> PgTuples {
        PgTuples {
            shared: self.shared.clone(),
        }
    }

    /// Reloads both snapshots from the database.
    ///
    /// # Errors
    ///
    /// The error of the read; the previous snapshot stays and the store becomes stale.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "strig.postgres.store.reload", level = "info", skip_all)
    )]
    pub async fn reload<C: GenericClient>(&self, client: &C) -> Result<(), PgQueryError> {
        self.reload_part(client, Reload::Both).await
    }

    /// Reloads the grant snapshot.
    ///
    /// # Errors
    ///
    /// As [`PgStore::reload`].
    pub async fn reload_grants<C: GenericClient>(&self, client: &C) -> Result<(), PgQueryError> {
        self.reload_part(client, Reload::Grants).await
    }

    /// Reloads the tuple snapshot.
    ///
    /// # Errors
    ///
    /// As [`PgStore::reload`].
    pub async fn reload_tuples<C: GenericClient>(&self, client: &C) -> Result<(), PgQueryError> {
        self.reload_part(client, Reload::Tuples).await
    }

    /// Did the last reload fail? Cleared by the next one that succeeds.
    pub fn is_stale(&self) -> bool {
        self.shared.stale.load(Ordering::Acquire)
    }

    async fn reload_part<C: GenericClient>(&self, client: &C, part: Reload) -> Result<(), PgQueryError> {
        let result = self.read_part(client, part).await;
        self.shared.stale.store(result.is_err(), Ordering::Release);
        result
    }

    async fn read_part<C: GenericClient>(&self, client: &C, part: Reload) -> Result<(), PgQueryError> {
        let grants = match part {
            Reload::Grants | Reload::Both => Some(self.tables.all_grants(client).await?),
            Reload::Tuples => None,
        };
        let tuples = match part {
            Reload::Tuples | Reload::Both => Some(self.tables.all_tuples(client).await?),
            Reload::Grants => None,
        };
        if let Some(grants) = grants {
            replace(&self.shared.grants, Arc::new(grants));
        }
        if let Some(tuples) = tuples {
            replace(&self.shared.tuples, Arc::new(TupleSnapshot::build(tuples)));
        }
        Ok(())
    }

    /// Reloads the snapshots on every notice of `changes` (the receiver of
    /// [`strig_sync::Hub::subscribe`]) until the hub is dropped.
    ///
    /// `connect` opens a connection for each reload (the caller spawns the connection driver, as
    /// [`connect`] does). A receiver that lagged lost notices, so it reloads everything. A reload that
    /// fails is retried every `retry` until it succeeds, and the store reads as stale meanwhile.
    pub fn follow<F, Fut, E>(
        &self,
        mut changes: broadcast::Receiver<Change>,
        connect: F,
        retry: Duration,
    ) -> JoinHandle<()>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Client, E>> + Send,
        E: Send,
    {
        let store = self.clone();
        tokio::spawn(async move {
            loop {
                let part = match changes.recv().await {
                    Ok(change) => match Reload::for_change(&change) {
                        Some(part) => part,
                        None => continue,
                    },
                    Err(RecvError::Lagged(_)) => Reload::Both,
                    Err(RecvError::Closed) => break,
                };
                loop {
                    let reloaded = match connect().await {
                        Ok(client) => store.reload_part(&client, part).await.is_ok(),
                        Err(_) => {
                            store.shared.stale.store(true, Ordering::Release);
                            false
                        }
                    };
                    if reloaded {
                        break;
                    }
                    tokio::time::sleep(retry).await;
                }
            }
        })
    }
}

/// Opens a connection without TLS and spawns its driver. For [`PgStore::follow`].
///
/// # Errors
///
/// The `tokio-postgres` error of the connection.
pub async fn connect(url: &str) -> Result<Client, tokio_postgres::Error> {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await?;
    tokio::spawn(connection);
    Ok(client)
}

/// [`GrantSource`] and [`GrantIndex`] over the snapshot of a [`PgStore`].
///
/// It delivers every grant, in the order of the indexed queries (by id): the engine filters by
/// permission, target, scope, subject, condition and window.
#[derive(Clone)]
pub struct PgGrants {
    shared: Arc<Shared>,
}

impl PgGrants {
    fn each(&self, mut keep: impl FnMut(&Grant) -> bool, visitor: &mut dyn FnMut(&Grant)) {
        let snapshot = read(&self.shared.grants);
        snapshot.iter().filter(|grant| keep(grant)).for_each(visitor);
    }
}

impl GrantSource for PgGrants {
    fn visit(&self, _: &Subject, _: &Resource, visitor: &mut dyn FnMut(&Grant)) {
        self.each(|_| true, visitor);
    }
}

impl GrantIndex for PgGrants {
    fn visit_by_permission(&self, permissions: &[&str], visitor: &mut dyn FnMut(&Grant)) {
        self.each(|grant| permissions.contains(&grant.permission.as_str()), visitor);
    }

    fn visit_by_target_kind(&self, kind: &str, visitor: &mut dyn FnMut(&Grant)) {
        self.each(|grant| grant.target.kind == kind, visitor);
    }

    fn visit_by_subject(&self, subject: &SubjectMatcher, visitor: &mut dyn FnMut(&Grant)) {
        self.each(|grant| &grant.subject == subject, visitor);
    }
}

/// [`TupleStore`] and [`TupleIndex`] over the snapshot of a [`PgStore`].
#[derive(Clone)]
pub struct PgTuples {
    shared: Arc<Shared>,
}

impl TupleStore for PgTuples {
    fn visit(&self, object: &ObjectRef, relation: &str, visitor: &mut dyn FnMut(&TupleSubject)) {
        let snapshot = read(&self.shared.tuples);
        if let Some(subjects) = snapshot.subjects.get(&(object.clone(), relation.to_string())) {
            subjects.iter().for_each(visitor);
        }
    }
}

impl TupleIndex for PgTuples {
    fn visit_objects(&self, kind: &str, visitor: &mut dyn FnMut(&ObjectRef)) {
        let snapshot = read(&self.shared.tuples);
        if let Some(objects) = snapshot.objects.get(kind) {
            objects.iter().for_each(visitor);
        }
    }

    fn visit_subjects(&self, object: &ObjectRef, visitor: &mut dyn FnMut(&str, &TupleSubject)) {
        let snapshot = read(&self.shared.tuples);
        if let Some(written) = snapshot.written.get(object) {
            written
                .iter()
                .for_each(|(relation, subject)| visitor(relation, subject));
        }
    }
}
