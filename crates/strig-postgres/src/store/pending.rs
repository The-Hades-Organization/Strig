//! Pending approval requests in Postgres.

use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use strig::{PendingError, PendingRequest, PendingStore};
use tokio::sync::{mpsc, oneshot};
use tokio_postgres::error::SqlState;
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::{Client, Config, GenericClient, NoTls, Socket};

use crate::query::{PgQueryError, PgTables};

fn store_error(error: impl std::fmt::Display) -> PendingError {
    PendingError::Store(error.to_string())
}

fn decode(text: &str) -> Result<PendingRequest, PendingError> {
    serde_json::from_str(text).map_err(store_error)
}

fn instant(value: u64) -> Result<i64, PendingError> {
    i64::try_from(value).map_err(|_| store_error("instant does not fit a bigint column"))
}

impl PgTables {
    /// Stores a new request.
    ///
    /// # Errors
    ///
    /// [`PendingError::Duplicate`] when the id is taken, [`PendingError::Store`] otherwise.
    pub async fn insert_pending<C: GenericClient>(
        &self,
        client: &C,
        request: &PendingRequest,
    ) -> Result<(), PendingError> {
        let data = serde_json::to_string(request).map_err(store_error)?;
        let (requested_at, expires_at) = columns(request)?;
        let sql = format!(
            "INSERT INTO {} (id, state, requested_at, expires_at, data) VALUES ($1, $2, $3, $4, $5::text::jsonb)",
            self.qualified(&self.pending)
        );
        client
            .execute(
                &sql,
                &[&request.id, &state_of(request), &requested_at, &expires_at, &data],
            )
            .await
            .map(|_| ())
            .map_err(|error| {
                if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
                    PendingError::Duplicate(request.id.clone())
                } else {
                    store_error(error)
                }
            })
    }

    /// The request with this id, whatever its status.
    ///
    /// # Errors
    ///
    /// [`PendingError::Store`] when the query fails or the stored row does not decode.
    pub async fn get_pending<C: GenericClient>(
        &self,
        client: &C,
        id: &str,
    ) -> Result<Option<PendingRequest>, PendingError> {
        let sql = format!("SELECT data::text FROM {} WHERE id = $1", self.qualified(&self.pending));
        let row = client.query_opt(&sql, &[&id]).await.map_err(store_error)?;
        row.map(|row| decode(row.get::<_, &str>(0))).transpose()
    }

    /// Replaces a request that is still pending, in one statement: a request decided meanwhile by
    /// another process is not touched.
    ///
    /// # Errors
    ///
    /// [`PendingError::Unknown`] when there is no such request, [`PendingError::NotPending`] when it was
    /// already decided, [`PendingError::Store`] otherwise.
    pub async fn update_pending<C: GenericClient>(
        &self,
        client: &C,
        request: &PendingRequest,
    ) -> Result<(), PendingError> {
        let data = serde_json::to_string(request).map_err(store_error)?;
        let (requested_at, expires_at) = columns(request)?;
        let table = self.qualified(&self.pending);
        let sql = format!(
            "UPDATE {table} SET state = $2, requested_at = $3, expires_at = $4, data = $5::text::jsonb \
             WHERE id = $1 AND state = 'pending'"
        );
        let changed = client
            .execute(
                &sql,
                &[&request.id, &state_of(request), &requested_at, &expires_at, &data],
            )
            .await
            .map_err(store_error)?;
        if changed > 0 {
            return Ok(());
        }
        let exists = client
            .query_opt(&format!("SELECT 1 FROM {table} WHERE id = $1"), &[&request.id])
            .await
            .map_err(store_error)?
            .is_some();
        Err(if exists {
            PendingError::NotPending(request.id.clone())
        } else {
            PendingError::Unknown(request.id.clone())
        })
    }

    /// Rewrites the data of a request without touching its decision: the row is changed only while
    /// its state is the one `request` carries, in one statement. It is how an elevation keeps its
    /// revocation and the closing of its review after the request was decided.
    ///
    /// # Errors
    ///
    /// [`PendingError::Unknown`] when there is no such request, [`PendingError::Store`] when its state
    /// is no longer the one given or the query fails.
    pub async fn annotate_pending<C: GenericClient>(
        &self,
        client: &C,
        request: &PendingRequest,
    ) -> Result<(), PendingError> {
        let data = serde_json::to_string(request).map_err(store_error)?;
        let table = self.qualified(&self.pending);
        let sql = format!("UPDATE {table} SET data = $3::text::jsonb WHERE id = $1 AND state = $2");
        let changed = client
            .execute(&sql, &[&request.id, &state_of(request), &data])
            .await
            .map_err(store_error)?;
        if changed > 0 {
            return Ok(());
        }
        let exists = client
            .query_opt(&format!("SELECT 1 FROM {table} WHERE id = $1"), &[&request.id])
            .await
            .map_err(store_error)?
            .is_some();
        Err(if exists {
            store_error("the request was decided differently meanwhile")
        } else {
            PendingError::Unknown(request.id.clone())
        })
    }

    /// Every request, oldest first.
    ///
    /// # Errors
    ///
    /// [`PendingError::Store`] when the query fails or a row does not decode.
    pub async fn list_pending<C: GenericClient>(&self, client: &C) -> Result<Vec<PendingRequest>, PendingError> {
        self.pending_where(client, "TRUE", &[]).await
    }

    /// The requests still pending whose expiry is at or before `now`: what
    /// [`strig::Approvals::expire_due`] closes. One indexed query.
    ///
    /// # Errors
    ///
    /// [`PendingError::Store`] when the query fails, a row does not decode or `now` does not fit.
    pub async fn due_pending<C: GenericClient>(
        &self,
        client: &C,
        now: u64,
    ) -> Result<Vec<PendingRequest>, PendingError> {
        let now = instant(now)?;
        self.pending_where(
            client,
            "state = 'pending' AND expires_at IS NOT NULL AND expires_at <= $1",
            &[&now],
        )
        .await
    }

    async fn pending_where<C: GenericClient>(
        &self,
        client: &C,
        condition: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<PendingRequest>, PendingError> {
        let sql = format!(
            "SELECT data::text FROM {} WHERE {condition} ORDER BY requested_at, id",
            self.qualified(&self.pending)
        );
        let rows = client.query(&sql, params).await.map_err(store_error)?;
        rows.iter().map(|row| decode(row.get::<_, &str>(0))).collect()
    }
}

fn state_of(request: &PendingRequest) -> &'static str {
    use strig::PendingStatus::{Approved, Expired, Pending, Rejected};
    match request.status {
        Pending => "pending",
        Approved { .. } => "approved",
        Rejected { .. } => "rejected",
        Expired { .. } => "expired",
    }
}

fn columns(request: &PendingRequest) -> Result<(i64, Option<i64>), PendingError> {
    Ok((
        instant(request.requested_at)?,
        request.expires_at.map(instant).transpose()?,
    ))
}

enum Op {
    Insert(PendingRequest),
    Get(String),
    Update(PendingRequest),
    Annotate(PendingRequest),
    List,
    Due(u64),
}

enum Reply {
    Done,
    One(Box<Option<PendingRequest>>),
    Many(Vec<PendingRequest>),
}

type Job = (Op, std_mpsc::Sender<Result<Reply, PendingError>>);

/// [`PendingStore`] over a Postgres table.
///
/// The trait is synchronous, so the store owns one connection on a thread of its own and a call waits
/// for the answer there. A call blocks the thread that makes it for the length of the round trip:
/// inside an async task use [`tokio::task::spawn_blocking`] (the approvals are rare and human-paced).
/// A call that does not answer within the timeout is a [`PendingError::Store`], and a dropped
/// connection is reopened on the next call.
pub struct PgPendingStore {
    jobs: mpsc::UnboundedSender<Job>,
    timeout: Duration,
}

impl PgPendingStore {
    /// Connects without TLS. See [`PgPendingStore::connect_with_tls`].
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] when the first connection fails.
    pub async fn connect(url: &str, tables: PgTables) -> Result<Self, PgQueryError> {
        Self::connect_with_tls(url, tables, NoTls).await
    }

    /// Connects with the given TLS connector and starts the worker thread.
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
            .name("strig-pg-pending".into())
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
                        let result = match &client {
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

    /// The pending requests due at `now`, for the sweep that expires them.
    ///
    /// # Errors
    ///
    /// [`PendingError::Store`] on a failed query or a timeout.
    pub fn due(&self, now: u64) -> Result<Vec<PendingRequest>, PendingError> {
        match self.call(Op::Due(now))? {
            Reply::Many(requests) => Ok(requests),
            _ => Err(store_error("unexpected reply")),
        }
    }

    fn call(&self, op: Op) -> Result<Reply, PendingError> {
        let (reply, answer) = std_mpsc::channel();
        self.jobs
            .send((op, reply))
            .map_err(|_| store_error("the store worker stopped"))?;
        answer
            .recv_timeout(self.timeout)
            .map_err(|_| store_error("the database did not answer in time"))?
    }
}

async fn run(tables: &PgTables, client: &Client, op: Op) -> Result<Reply, PendingError> {
    match op {
        Op::Insert(request) => tables.insert_pending(client, &request).await.map(|()| Reply::Done),
        Op::Get(id) => tables.get_pending(client, &id).await.map(|r| Reply::One(Box::new(r))),
        Op::Update(request) => tables.update_pending(client, &request).await.map(|()| Reply::Done),
        Op::Annotate(request) => tables.annotate_pending(client, &request).await.map(|()| Reply::Done),
        Op::List => tables.list_pending(client).await.map(Reply::Many),
        Op::Due(now) => tables.due_pending(client, now).await.map(Reply::Many),
    }
}

impl PendingStore for PgPendingStore {
    fn insert(&self, request: PendingRequest) -> Result<(), PendingError> {
        self.call(Op::Insert(request)).map(|_| ())
    }

    fn get(&self, id: &str) -> Result<Option<PendingRequest>, PendingError> {
        match self.call(Op::Get(id.to_string()))? {
            Reply::One(request) => Ok(*request),
            _ => Err(store_error("unexpected reply")),
        }
    }

    fn update(&self, request: PendingRequest) -> Result<(), PendingError> {
        self.call(Op::Update(request)).map(|_| ())
    }

    fn annotate(&self, request: PendingRequest) -> Result<(), PendingError> {
        self.call(Op::Annotate(request)).map(|_| ())
    }

    fn list(&self) -> Result<Vec<PendingRequest>, PendingError> {
        match self.call(Op::List)? {
            Reply::Many(requests) => Ok(requests),
            _ => Err(store_error("unexpected reply")),
        }
    }
}
