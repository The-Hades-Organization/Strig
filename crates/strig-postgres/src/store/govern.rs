//! Writing a governed change and its notice in the caller's transaction.

use strig::{Anchor, Grant, Mutation, RoleAssignment};
use strig_sync::Change;
use tokio_postgres::GenericClient;

use crate::notify;
use crate::query::{PgQueryError, PgTables};

fn grant_scope(grant: &Grant) -> Anchor {
    match &grant.target.id {
        Some(id) => Anchor::new(grant.target.kind.clone(), id.clone()),
        None => Anchor::global(),
    }
}

fn role_scope(role: &RoleAssignment) -> Anchor {
    role.scope.clone().unwrap_or_else(Anchor::global)
}

impl PgTables {
    /// Serialises governed changes: holds an advisory lock until the transaction ends.
    ///
    /// Judge-then-write is a read-modify-write. Call this first in the transaction, then read the
    /// grants with [`PgTables::all_grants`] inside it, so two instances never judge a change against
    /// the same stale set and both commit.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] when the statement fails.
    pub async fn lock_governance<C: GenericClient>(&self, client: &C) -> Result<(), PgQueryError> {
        client
            .execute(
                "SELECT pg_advisory_xact_lock(hashtext($1))",
                &[&format!("strig-governance:{}", self.qualified(&self.grants))],
            )
            .await?;
        Ok(())
    }

    /// Writes what `mutation` changes (a grant, or a role of a subject) and sends its notice on
    /// `channel`, both through `client`. Pass the transaction: the notice leaves on commit, if and only
    /// if the change was written. Returns the notice sent, or `None` when the change touched nothing
    /// (removing a grant or a role that was not there).
    ///
    /// The mutation must have been accepted by [`strig::Governance::apply`]; this writes it as is.
    ///
    /// # Errors
    ///
    /// Whatever the writes return, or [`PgQueryError::Notify`] when the notice does not fit
    /// [`crate::MAX_PAYLOAD`] or the statement fails.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "strig.postgres.store.commit_mutation", level = "info", skip_all)
    )]
    pub async fn commit_mutation<C: GenericClient + Sync>(
        &self,
        client: &C,
        channel: &str,
        mutation: &Mutation,
    ) -> Result<Option<Change>, PgQueryError> {
        let change = match mutation {
            Mutation::Add(grant) => {
                self.put_grant(client, grant).await?;
                Some(Change::grants(grant_scope(grant)).with_id(grant.id.clone()))
            }
            Mutation::Remove { id } => self
                .delete_grant(client, id)
                .await?
                .map(|grant| Change::grants(grant_scope(&grant)).with_id(grant.id)),
            Mutation::AssignRole { subject, role } => {
                self.assign_role(client, subject, role).await?;
                Some(role_change(subject.id.as_deref(), role))
            }
            Mutation::RevokeRole { subject, role } => self
                .revoke_role(client, subject, role)
                .await?
                .then(|| role_change(subject.id.as_deref(), role)),
        };
        if let Some(change) = &change {
            notify(client, channel, change).await?;
        }
        Ok(change)
    }
}

fn role_change(subject: Option<&str>, role: &RoleAssignment) -> Change {
    Change::roles(subject.unwrap_or_default(), role_scope(role))
}
