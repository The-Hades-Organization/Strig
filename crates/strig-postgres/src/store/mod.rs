//! Production persistence in Postgres: grants, ReBAC tuples, role assignments and pending approval
//! requests, with versioned migrations.
//!
//! - [`migrate`] / [`migrate_with`]: the schema, embedded and versioned, safe to run on every boot.
//! - [`PgStore`]: a loaded snapshot of grants and tuples serving the synchronous
//!   [`strig::GrantSource`], [`strig::GrantIndex`], [`strig::TupleStore`] and [`strig::TupleIndex`],
//!   reloaded when a [`strig_sync::Change`] arrives.
//! - [`PgTables`](crate::query::PgTables): the writes (`put_grant`, `delete_grant`, `put_tuple`,
//!   `assign_role`, `commit_mutation`, ...), all generic over a client or a transaction.
//! - [`PgPendingStore`]: a [`strig::PendingStore`] with expiry.

mod govern;
mod migrate;
mod pending;
mod roles;
mod snapshot;

pub use migrate::{LATEST_VERSION, migrate, migrate_with, schema_version};
pub use pending::PgPendingStore;
pub use snapshot::{PgGrants, PgStore, PgTuples, connect};
