//! Role assignments per subject.

use strig::{Anchor, RoleAssignment, Subject};
use tokio_postgres::GenericClient;

use crate::query::{PgQueryError, PgTables, window_bound};

fn scope_columns(role: &RoleAssignment) -> Result<(&str, &str), PgQueryError> {
    match &role.scope {
        None => Ok(("", "")),
        Some(Anchor { kind, .. }) if kind.is_empty() => {
            Err(PgQueryError::Invalid("role scope with an empty kind".into()))
        }
        Some(Anchor { id: Some(id), .. }) if id.is_empty() => {
            Err(PgQueryError::Invalid("role scope with an empty id".into()))
        }
        Some(Anchor { kind, id }) => Ok((kind, id.as_deref().unwrap_or(""))),
    }
}

fn require_id(subject: &Subject) -> Result<&str, PgQueryError> {
    subject
        .id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| PgQueryError::Invalid("a subject without an id has no stored roles".into()))
}

impl PgTables {
    /// Gives `role` to the subject, replacing the window of an assignment with the same role and
    /// scope.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Invalid`] for a subject without an id, an empty scope or an inverted window;
    /// [`PgQueryError::InstantOutOfRange`] or [`PgQueryError::Database`] otherwise.
    pub async fn assign_role<C: GenericClient>(
        &self,
        client: &C,
        subject: &Subject,
        role: &RoleAssignment,
    ) -> Result<(), PgQueryError> {
        let id = require_id(subject)?;
        role.check_window()
            .map_err(|error| PgQueryError::Invalid(error.to_string()))?;
        let (scope_kind, scope_id) = scope_columns(role)?;
        let (valid_from, valid_until) = (window_bound(role.valid_from)?, window_bound(role.valid_until)?);
        let sql = format!(
            "INSERT INTO {} (subject_kind, subject_id, role, scope_kind, scope_id, valid_from, valid_until) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (subject_kind, subject_id, role, scope_kind, scope_id) \
             DO UPDATE SET valid_from = $6, valid_until = $7",
            self.qualified(&self.roles)
        );
        client
            .execute(
                &sql,
                &[
                    &subject.kind,
                    &id,
                    &role.role,
                    &scope_kind,
                    &scope_id,
                    &valid_from,
                    &valid_until,
                ],
            )
            .await?;
        Ok(())
    }

    /// Takes `role` from the subject, comparing role and scope (as [`strig::Mutation::RevokeRole`]
    /// does). `false` if the subject did not have it.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Invalid`] for a subject without an id or an empty scope;
    /// [`PgQueryError::Database`] otherwise.
    pub async fn revoke_role<C: GenericClient>(
        &self,
        client: &C,
        subject: &Subject,
        role: &RoleAssignment,
    ) -> Result<bool, PgQueryError> {
        let id = require_id(subject)?;
        let (scope_kind, scope_id) = scope_columns(role)?;
        let sql = format!(
            "DELETE FROM {} WHERE subject_kind = $1 AND subject_id = $2 AND role = $3 \
             AND scope_kind = $4 AND scope_id = $5",
            self.qualified(&self.roles)
        );
        let removed = client
            .execute(&sql, &[&subject.kind, &id, &role.role, &scope_kind, &scope_id])
            .await?;
        Ok(removed > 0)
    }

    /// The assignments of a subject, ordered by role and scope.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] when the query fails.
    pub async fn roles_of<C: GenericClient>(
        &self,
        client: &C,
        kind: &str,
        id: &str,
    ) -> Result<Vec<RoleAssignment>, PgQueryError> {
        let sql = format!(
            "SELECT role, scope_kind, scope_id, valid_from, valid_until FROM {} \
             WHERE subject_kind = $1 AND subject_id = $2 ORDER BY role, scope_kind, scope_id",
            self.qualified(&self.roles)
        );
        let rows = client.query(&sql, &[&kind, &id]).await?;
        Ok(rows
            .iter()
            .map(|row| {
                let scope_kind: String = row.get(1);
                let scope_id: String = row.get(2);
                let scope = (!scope_kind.is_empty()).then(|| Anchor {
                    kind: scope_kind,
                    id: (!scope_id.is_empty()).then_some(scope_id),
                });
                let from: Option<i64> = row.get(3);
                let until: Option<i64> = row.get(4);
                RoleAssignment {
                    role: row.get(0),
                    scope,
                    valid_from: from.and_then(|v| u64::try_from(v).ok()),
                    valid_until: until.and_then(|v| u64::try_from(v).ok()),
                }
            })
            .collect())
    }

    /// The [`Subject`] with its stored roles, ready for the engine: a `user` carries the
    /// `authenticated` principal (as [`Subject::user`]), any other kind carries none. A subject with
    /// no roles comes back with none; it is not an error.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] when the query fails.
    pub async fn subject<C: GenericClient>(&self, client: &C, kind: &str, id: &str) -> Result<Subject, PgQueryError> {
        let mut subject = if kind == "user" {
            Subject::user(id)
        } else {
            Subject::of_kind(kind, id)
        };
        for assignment in self.roles_of(client, kind, id).await? {
            subject = subject.with_assignment(assignment);
        }
        Ok(subject)
    }
}
