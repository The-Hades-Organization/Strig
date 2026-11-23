//! Index queries and `WHERE` translation for listings.
//!
//! The grants and the ReBAC tuples live in two tables ([`PgTables::schema_sql`]). The `grants_by_*`
//! and `tuples_of_*` functions load the rows that the core's `GrantIndex` and `TupleIndex` visit, so
//! a listing reads only what it needs. [`filter_where`] turns an [`AccessFilter`] into a `WHERE`
//! clause over the table that holds the resources.
//!
//! Every value reaches the database as a bound parameter. The only text spliced into SQL is table
//! and column names, which are validated as plain identifiers when the [`PgTables`] or [`PgTable`]
//! is built and then quoted.

use std::collections::BTreeMap;

use themis::query::FilterResidual;
use themis::{AccessFilter, Expr, GLOBAL, Grant, ObjectRef, PathLayout, SubjectMatcher, Tuple};
use tokio_postgres::GenericClient;
use tokio_postgres::types::ToSql;

use crate::{WindowColumns, quote_ident, window_predicate};

/// Error of the index queries and of the `WHERE` translation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PgQueryError {
    /// A table or column name is not a plain identifier (`[A-Za-z_][A-Za-z0-9_]*`), or a table name
    /// is too long for the names of its indexes to fit in the 63 bytes Postgres keeps.
    #[error("invalid identifier: {0:?}")]
    InvalidIdentifier(String),
    /// The filter reads a resource attribute that the [`PgTable`] has no column for.
    #[error("no column mapped for resource attribute {0:?}")]
    UnmappedAttribute(String),
    /// The filter reads a step of the path whose kind the [`PgTable`] has no column for. Reading it
    /// as "no row has it" would open access under a deny, so it is an error.
    #[error("no column mapped for path kind {0:?}")]
    UnmappedKind(String),
    /// The expression has a node this version of the translation does not know. It is an error
    /// because reading it as `FALSE` could open access under a deny.
    #[error("expression node has no SQL form")]
    UnsupportedExpr,
    /// A userset tuple with an empty relation would be stored as a direct tuple, which grants to a
    /// different subject than the caller meant.
    #[error("userset tuple with an empty relation")]
    EmptyUsersetRelation,
    /// The expression carries a residue, which has no SQL form.
    #[error("expression has a residue; translate with `filter_where`")]
    Residual,
    /// A validity bound or the instant of a query does not fit in a `bigint` column.
    #[error(transparent)]
    InstantOutOfRange(#[from] crate::InstantOutOfRange),
    #[error("database error")]
    Database(#[from] tokio_postgres::Error),
    #[error("stored grant is not valid JSON")]
    Decode(#[from] serde_json::Error),
}

/// A validity bound as the `bigint` the grant table stores.
fn window_bound(bound: Option<u64>) -> Result<Option<i64>, PgQueryError> {
    bound
        .map(|value| i64::try_from(value).map_err(|_| crate::InstantOutOfRange(value).into()))
        .transpose()
}

/// Postgres keeps 63 bytes of an identifier and silently cuts the rest.
const MAX_IDENTIFIER: usize = 63;

/// Longest suffix added to a table name to name one of its indexes (`_target_kind_idx`).
const INDEX_SUFFIX: usize = 16;

fn identifier_up_to(name: impl Into<String>, max: usize) -> Result<String, PgQueryError> {
    let name = name.into();
    let mut chars = name.chars();
    let valid = name.len() <= max
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if valid {
        Ok(name)
    } else {
        Err(PgQueryError::InvalidIdentifier(name))
    }
}

fn identifier(name: impl Into<String>) -> Result<String, PgQueryError> {
    identifier_up_to(name, MAX_IDENTIFIER)
}

/// A table name that leaves room for the suffix of its index names, so two indexes never collide
/// after Postgres truncates them.
fn table_identifier(name: impl Into<String>) -> Result<String, PgQueryError> {
    identifier_up_to(name, MAX_IDENTIFIER - INDEX_SUFFIX)
}

/// Names of the grant table and of the tuple table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgTables {
    grants: String,
    tuples: String,
}

impl Default for PgTables {
    fn default() -> Self {
        Self {
            grants: "themis_grants".to_string(),
            tuples: "themis_tuples".to_string(),
        }
    }
}

impl PgTables {
    /// # Errors
    ///
    /// [`PgQueryError::InvalidIdentifier`] when a name is not a plain identifier or is longer than
    /// 47 bytes (its index names would not fit in the 63 bytes of a Postgres identifier).
    pub fn new(grants: impl Into<String>, tuples: impl Into<String>) -> Result<Self, PgQueryError> {
        Ok(Self {
            grants: table_identifier(grants)?,
            tuples: table_identifier(tuples)?,
        })
    }

    /// DDL of both tables with the indexes the queries of this module use. Safe to run twice.
    ///
    /// The `permission` and `target_kind` columns must agree with the JSON in `data`, which is what
    /// the engine reads; a `CHECK` rejects a row written outside [`PgTables::put_grant`] that
    /// disagrees, so an indexed query never skips a grant (a deny) the engine would apply. A table
    /// created by an earlier version has no such `CHECK`: add it before relying on it. The `effect`,
    /// `valid_from` and `valid_until` columns (milliseconds since the Unix epoch) feed the window
    /// predicate of the grant queries and are held to the JSON the same way.
    pub fn schema_sql(&self) -> String {
        let (grants, tuples) = (quote_ident(&self.grants), quote_ident(&self.tuples));
        let index = |table: &str, suffix: &str| quote_ident(&format!("{table}_{suffix}"));
        format!(
            "CREATE TABLE IF NOT EXISTS {grants} (\
                id text PRIMARY KEY, \
                permission text NOT NULL, \
                subject_kind text NOT NULL, \
                subject_value text, \
                target_kind text NOT NULL, \
                effect text NOT NULL, \
                valid_from bigint, \
                valid_until bigint, \
                data jsonb NOT NULL, \
                CHECK (permission = data->>'permission'), \
                CHECK (target_kind = data->'target'->>'kind'), \
                CHECK (effect = data->>'effect'), \
                CHECK (valid_from IS NOT DISTINCT FROM (data->>'validFrom')::bigint), \
                CHECK (valid_until IS NOT DISTINCT FROM (data->>'validUntil')::bigint));\
            CREATE INDEX IF NOT EXISTS {gp} ON {grants} (permission);\
            CREATE INDEX IF NOT EXISTS {gt} ON {grants} (target_kind);\
            CREATE INDEX IF NOT EXISTS {gs} ON {grants} (subject_kind, subject_value);\
            CREATE TABLE IF NOT EXISTS {tuples} (\
                object_kind text NOT NULL, \
                object_id text NOT NULL, \
                relation text NOT NULL, \
                subject_kind text NOT NULL, \
                subject_id text NOT NULL, \
                subject_relation text NOT NULL DEFAULT '', \
                PRIMARY KEY (object_kind, object_id, relation, subject_kind, subject_id, subject_relation));\
            CREATE INDEX IF NOT EXISTS {tk} ON {tuples} (object_kind);",
            gp = index(&self.grants, "permission_idx"),
            gt = index(&self.grants, "target_kind_idx"),
            gs = index(&self.grants, "subject_idx"),
            tk = index(&self.tuples, "object_kind_idx"),
        )
    }

    /// Writes a grant (replacing the one with the same id).
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Decode`] when the grant does not serialize, [`PgQueryError::Database`] otherwise.
    pub async fn put_grant<C: GenericClient>(&self, client: &C, grant: &Grant) -> Result<(), PgQueryError> {
        let (kind, value) = subject_columns(&grant.subject);
        let data = serde_json::to_string(grant)?;
        let sql = format!(
            "INSERT INTO {} (id, permission, subject_kind, subject_value, target_kind, effect, valid_from, \
             valid_until, data) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::jsonb) \
             ON CONFLICT (id) DO UPDATE SET permission = $2, subject_kind = $3, subject_value = $4, \
             target_kind = $5, effect = $6, valid_from = $7, valid_until = $8, data = $9::text::jsonb",
            quote_ident(&self.grants)
        );
        let effect = match grant.effect {
            themis::Effect::Allow => "allow",
            themis::Effect::Deny => "deny",
        };
        let (valid_from, valid_until) = (window_bound(grant.valid_from)?, window_bound(grant.valid_until)?);
        client
            .execute(
                &sql,
                &[
                    &grant.id,
                    &grant.permission,
                    &kind,
                    &value,
                    &grant.target.kind,
                    &effect,
                    &valid_from,
                    &valid_until,
                    &data,
                ],
            )
            .await?;
        Ok(())
    }

    /// Writes a tuple (a repeated one is left as it is).
    ///
    /// # Errors
    ///
    /// [`PgQueryError::EmptyUsersetRelation`] for a userset with an empty relation,
    /// [`PgQueryError::Database`] when the statement fails.
    pub async fn put_tuple<C: GenericClient>(&self, client: &C, tuple: &Tuple) -> Result<(), PgQueryError> {
        let (subject, set_relation) = match &tuple.subject {
            themis::TupleSubject::Object(object) => (object, ""),
            themis::TupleSubject::Userset(_, relation) if relation.is_empty() => {
                return Err(PgQueryError::EmptyUsersetRelation);
            }
            themis::TupleSubject::Userset(object, relation) => (object, relation.as_str()),
        };
        let sql = format!(
            "INSERT INTO {} (object_kind, object_id, relation, subject_kind, subject_id, subject_relation) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            quote_ident(&self.tuples)
        );
        client
            .execute(
                &sql,
                &[
                    &tuple.object.kind,
                    &tuple.object.id,
                    &tuple.relation,
                    &subject.kind,
                    &subject.id,
                    &set_relation,
                ],
            )
            .await?;
        Ok(())
    }

    /// Grants of any of the permission keys (the permission and what implies it).
    ///
    /// `now` is the instant of the query, in milliseconds since the Unix epoch: the rows come back
    /// through [`window_predicate`], so a grant outside its window is left out. Without `now` the
    /// filter fails closed as the engine does: a grant with a window is dropped unless it may be a
    /// deny.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`], [`PgQueryError::Decode`] or [`PgQueryError::InstantOutOfRange`].
    pub async fn grants_by_permission<C: GenericClient>(
        &self,
        client: &C,
        permissions: &[&str],
        now: Option<u64>,
    ) -> Result<Vec<Grant>, PgQueryError> {
        let keys: Vec<String> = permissions.iter().map(|p| (*p).to_string()).collect();
        self.grants_where(client, "permission = ANY($1::text[])", &[&keys], now)
            .await
    }

    /// Grants whose target is of `kind` (`global` for the implicit step). `now` as in
    /// [`PgTables::grants_by_permission`].
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`], [`PgQueryError::Decode`] or [`PgQueryError::InstantOutOfRange`].
    pub async fn grants_by_target_kind<C: GenericClient>(
        &self,
        client: &C,
        kind: &str,
        now: Option<u64>,
    ) -> Result<Vec<Grant>, PgQueryError> {
        self.grants_where(client, "target_kind = $1", &[&kind], now).await
    }

    /// Grants to exactly this subject matcher. `now` as in [`PgTables::grants_by_permission`].
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`], [`PgQueryError::Decode`] or [`PgQueryError::InstantOutOfRange`].
    pub async fn grants_by_subject<C: GenericClient>(
        &self,
        client: &C,
        subject: &SubjectMatcher,
        now: Option<u64>,
    ) -> Result<Vec<Grant>, PgQueryError> {
        let (kind, value) = subject_columns(subject);
        self.grants_where(
            client,
            "subject_kind = $1 AND subject_value IS NOT DISTINCT FROM $2",
            &[&kind, &value],
            now,
        )
        .await
    }

    /// The grant query for `condition` (using `$1..$bound`) with the window filter, and the instant
    /// to bind after the caller's parameters.
    fn grants_sql(
        &self,
        condition: &str,
        bound: usize,
        now: Option<u64>,
    ) -> Result<(String, Option<i64>), PgQueryError> {
        let window = window_predicate(&WindowColumns::default(), bound + 1, now)?;
        let sql = format!(
            "SELECT data::text FROM {} WHERE {condition} AND {} ORDER BY id",
            quote_ident(&self.grants),
            window.sql
        );
        Ok((sql, window.param))
    }

    async fn grants_where<C: GenericClient>(
        &self,
        client: &C,
        condition: &str,
        params: &[&(dyn ToSql + Sync)],
        now: Option<u64>,
    ) -> Result<Vec<Grant>, PgQueryError> {
        let (sql, instant) = self.grants_sql(condition, params.len(), now)?;
        let mut bound: Vec<&(dyn ToSql + Sync)> = params.to_vec();
        if let Some(instant) = &instant {
            bound.push(instant);
        }
        let rows = client.query(&sql, &bound).await?;
        rows.iter()
            .map(|row| serde_json::from_str(row.get::<_, &str>(0)).map_err(PgQueryError::from))
            .collect()
    }

    /// Tuples written on objects of `kind`.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] when the query fails.
    pub async fn tuples_of_kind<C: GenericClient>(&self, client: &C, kind: &str) -> Result<Vec<Tuple>, PgQueryError> {
        self.tuples_where(client, "object_kind = $1", &[&kind]).await
    }

    /// Tuples written on one object.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::Database`] when the query fails.
    pub async fn tuples_of_object<C: GenericClient>(
        &self,
        client: &C,
        object: &ObjectRef,
    ) -> Result<Vec<Tuple>, PgQueryError> {
        self.tuples_where(
            client,
            "object_kind = $1 AND object_id = $2",
            &[&object.kind, &object.id],
        )
        .await
    }

    async fn tuples_where<C: GenericClient>(
        &self,
        client: &C,
        condition: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Tuple>, PgQueryError> {
        let sql = format!(
            "SELECT object_kind, object_id, relation, subject_kind, subject_id, subject_relation \
             FROM {} WHERE {condition} ORDER BY object_kind, object_id, relation, subject_kind, subject_id, \
             subject_relation",
            quote_ident(&self.tuples)
        );
        let rows = client.query(&sql, params).await?;
        Ok(rows
            .iter()
            .map(|row| {
                let object = ObjectRef::new(row.get::<_, String>(0), row.get::<_, String>(1));
                let subject = ObjectRef::new(row.get::<_, String>(3), row.get::<_, String>(4));
                let set_relation: String = row.get(5);
                if set_relation.is_empty() {
                    Tuple::new(object, row.get::<_, String>(2), subject)
                } else {
                    Tuple::userset(object, row.get::<_, String>(2), subject, set_relation)
                }
            })
            .collect())
    }
}

/// How a grant's subject matcher is stored: a kind and an optional value.
fn subject_columns(subject: &SubjectMatcher) -> (&'static str, Option<String>) {
    match subject {
        SubjectMatcher::User { id } => ("user", Some(id.clone())),
        SubjectMatcher::Role { id } => ("role", Some(id.clone())),
        SubjectMatcher::Principal { name } => ("principal", Some(name.clone())),
        SubjectMatcher::Relation { relation } => ("relation", Some(relation.clone())),
        SubjectMatcher::Any => ("any", None),
    }
}

// ---------------------------------------------------------------------------------------------
// WHERE translation
// ---------------------------------------------------------------------------------------------

/// The table that holds the resources of a listing, and the column of each step of the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgTable {
    id_column: String,
    kind: String,
    path_columns: BTreeMap<String, String>,
    attr_columns: BTreeMap<String, String>,
}

impl PgTable {
    /// `kind` is the resource kind listed and `id_column` the column with its id.
    ///
    /// # Errors
    ///
    /// [`PgQueryError::InvalidIdentifier`] when the column is not a plain identifier.
    pub fn new(kind: impl Into<String>, id_column: impl Into<String>) -> Result<Self, PgQueryError> {
        Ok(Self {
            id_column: identifier(id_column)?,
            kind: kind.into(),
            path_columns: BTreeMap::new(),
            attr_columns: BTreeMap::new(),
        })
    }

    /// Column that holds the id of a broader step of the path (`project_id` for `project`).
    ///
    /// # Errors
    ///
    /// [`PgQueryError::InvalidIdentifier`] when the column is not a plain identifier.
    pub fn path_column(mut self, kind: impl Into<String>, column: impl Into<String>) -> Result<Self, PgQueryError> {
        self.path_columns.insert(kind.into(), identifier(column)?);
        Ok(self)
    }

    /// Column that holds a resource attribute that a rule reads (the `owner` of an ownership rule).
    ///
    /// # Errors
    ///
    /// [`PgQueryError::InvalidIdentifier`] when the column is not a plain identifier.
    pub fn attr_column(mut self, attr: impl Into<String>, column: impl Into<String>) -> Result<Self, PgQueryError> {
        self.attr_columns.insert(attr.into(), identifier(column)?);
        Ok(self)
    }

    fn column_of(&self, kind: &str) -> Option<&str> {
        if kind == self.kind {
            Some(&self.id_column)
        } else {
            self.path_columns.get(kind).map(String::as_str)
        }
    }
}

/// A bound parameter of a translated filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PgParam {
    Text(String),
    TextArray(Vec<String>),
}

impl PgParam {
    pub fn as_sql(&self) -> &(dyn ToSql + Sync) {
        match self {
            PgParam::Text(text) => text,
            PgParam::TextArray(items) => items,
        }
    }
}

/// A listing as SQL.
///
/// The two conditions are separate queries, so each carries its own parameters: binding the
/// parameters of one to the other fails, because Postgres rejects a statement bound to a different
/// number of parameters than it declares.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PgFilter {
    /// Condition that every allowed row meets (the rows it also admits are settled by `residual`).
    pub where_sql: String,
    /// Parameters of `where_sql`, from `$first_param` onwards.
    pub where_params: Vec<PgParam>,
    /// Condition that a row meets only if it is allowed, whatever the residue says. Present only
    /// when there is a residue: the rows in `where_sql` but not here are the ones to check.
    pub settled_sql: Option<String>,
    /// Parameters of `settled_sql`, from `$first_param` onwards (empty without `settled_sql`).
    pub settled_params: Vec<PgParam>,
    /// What the database cannot settle: check the rows of `where_sql` outside `settled_sql` one by
    /// one with the engine.
    pub residual: Vec<FilterResidual>,
}

impl PgFilter {
    /// The parameters of `where_sql` as the slice `tokio-postgres` takes, after the caller's own.
    pub fn where_sql_params(&self) -> Vec<&(dyn ToSql + Sync)> {
        self.where_params.iter().map(PgParam::as_sql).collect()
    }

    /// The parameters of `settled_sql` as the slice `tokio-postgres` takes, after the caller's own.
    pub fn settled_sql_params(&self) -> Vec<&(dyn ToSql + Sync)> {
        self.settled_params.iter().map(PgParam::as_sql).collect()
    }
}

/// Translates a listing into a parameterized `WHERE` condition over `table`. Placeholders start at
/// `$first_param`, so the caller can add its own (tenant, paging) before them.
///
/// Every atom is `TRUE` or `FALSE`, never `NULL`: a row whose path or attribute column is `NULL`
/// does not have that step or attribute, which is what [`themis::Engine::check`] sees, and a `NOT`
/// over it holds. Without that, `NOT (project_id = $1)` would be `NULL` and drop a row that a deny
/// elsewhere does not reach.
///
/// # Errors
///
/// [`PgQueryError::UnmappedAttribute`] when the filter reads an attribute with no column;
/// [`PgQueryError::UnmappedKind`] when it reads a path kind with no column. Both fail loudly because
/// a deny turns a "no row" reading into an allow.
pub fn filter_where(
    filter: &AccessFilter,
    layout: &PathLayout,
    table: &PgTable,
    first_param: usize,
) -> Result<PgFilter, PgQueryError> {
    let expr = filter.expr(layout);
    let (lower, upper) = expr.bounds();
    let mut where_params = Vec::new();
    let where_sql = to_sql(&upper, table, first_param, &mut where_params)?;
    let mut settled_params = Vec::new();
    let settled_sql = if expr.has_residual() {
        Some(to_sql(&lower, table, first_param, &mut settled_params)?)
    } else {
        None
    };
    Ok(PgFilter {
        where_sql,
        where_params,
        settled_sql,
        settled_params,
        residual: filter.residual_for(layout),
    })
}

/// Translates a structural expression with no residue.
///
/// # Errors
///
/// [`PgQueryError::Residual`] when the expression has a residue; the errors of [`filter_where`]
/// for unmapped attributes and kinds.
pub fn to_where(expr: &Expr, table: &PgTable, first_param: usize) -> Result<(String, Vec<PgParam>), PgQueryError> {
    if expr.has_residual() {
        return Err(PgQueryError::Residual);
    }
    let mut params = Vec::new();
    let sql = to_sql(expr, table, first_param, &mut params)?;
    Ok((sql, params))
}

fn placeholder(first_param: usize, params: &mut Vec<PgParam>, param: PgParam) -> String {
    params.push(param);
    format!("${}", first_param + params.len() - 1)
}

/// The path goes through a step of `kind`, with this id or with any id.
fn step_sql(
    table: &PgTable,
    kind: &str,
    id: Option<&str>,
    first_param: usize,
    params: &mut Vec<PgParam>,
) -> Result<String, PgQueryError> {
    if kind == GLOBAL {
        return Ok("TRUE".to_string());
    }
    let column = table
        .column_of(kind)
        .ok_or_else(|| PgQueryError::UnmappedKind(kind.to_string()))?;
    Ok(match id {
        // A column holds the id of the step, so a step of the kind is there when it is set.
        None => format!("{} IS NOT NULL", quote_ident(column)),
        Some(id) => format!(
            "({} = {}) IS TRUE",
            quote_ident(column),
            placeholder(first_param, params, PgParam::Text(id.to_string()))
        ),
    })
}

fn to_sql(expr: &Expr, table: &PgTable, first_param: usize, params: &mut Vec<PgParam>) -> Result<String, PgQueryError> {
    Ok(match expr {
        Expr::True => "TRUE".to_string(),
        Expr::False | Expr::Residual(_) => "FALSE".to_string(),
        Expr::Within(anchor) => step_sql(table, &anchor.kind, anchor.id.as_deref(), first_param, params)?,
        Expr::OnPath(selector) => step_sql(table, &selector.kind, selector.id.as_deref(), first_param, params)?,
        Expr::AnchorIn { kind, ids } => {
            let column = table
                .column_of(kind)
                .ok_or_else(|| PgQueryError::UnmappedKind(kind.clone()))?;
            if ids.is_empty() {
                "FALSE".to_string()
            } else {
                format!(
                    "({} = ANY({}::text[])) IS TRUE",
                    quote_ident(column),
                    placeholder(first_param, params, PgParam::TextArray(ids.iter().cloned().collect()))
                )
            }
        }
        Expr::AttrEq { attr, value } => {
            let column = table
                .attr_columns
                .get(attr)
                .ok_or_else(|| PgQueryError::UnmappedAttribute(attr.clone()))?;
            format!(
                "({} = {}) IS TRUE",
                quote_ident(column),
                placeholder(first_param, params, PgParam::Text(value.clone()))
            )
        }
        Expr::Not(inner) => format!("NOT ({})", to_sql(inner, table, first_param, params)?),
        Expr::And(items) if items.is_empty() => "TRUE".to_string(),
        Expr::Or(items) if items.is_empty() => "FALSE".to_string(),
        Expr::And(items) => join(items, " AND ", table, first_param, params)?,
        Expr::Or(items) => join(items, " OR ", table, first_param, params)?,
        // `Expr` is non-exhaustive: a node added later must not read as FALSE under a deny.
        _ => return Err(PgQueryError::UnsupportedExpr),
    })
}

fn join(
    items: &[Expr],
    separator: &str,
    table: &PgTable,
    first_param: usize,
    params: &mut Vec<PgParam>,
) -> Result<String, PgQueryError> {
    let parts: Result<Vec<String>, PgQueryError> = items
        .iter()
        .map(|item| to_sql(item, table, first_param, params).map(|sql| format!("({sql})")))
        .collect();
    Ok(parts?.join(separator))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use themis::Anchor;

    use super::*;

    fn table() -> PgTable {
        PgTable::new("document", "id")
            .unwrap()
            .path_column("project", "project_id")
            .unwrap()
            .path_column("org", "org_id")
            .unwrap()
            .attr_column("owner", "owner_id")
            .unwrap()
    }

    #[test]
    fn grant_queries_filter_by_window_and_bind_the_instant() {
        let tables = PgTables::new("themis_grants", "themis_tuples").unwrap();
        let (with_now, instant) = tables.grants_sql("target_kind = $1", 1, Some(150)).unwrap();
        assert!(with_now.contains("valid_from") && with_now.contains("valid_until"));
        assert!(with_now.contains("$2"), "the instant is the next parameter: {with_now}");
        assert_eq!(instant, Some(150));
        let (without, none) = tables.grants_sql("target_kind = $1", 1, None).unwrap();
        assert!(none.is_none());
        assert!(
            without.contains("valid_until"),
            "no instant still filters windows: {without}"
        );
        assert!(tables.grants_sql("x", 1, Some(u64::MAX)).is_err());
    }

    #[test]
    fn identifiers_are_validated() {
        assert!(PgTable::new("document", "id; DROP TABLE x").is_err());
        assert!(PgTable::new("document", "").is_err());
        assert!(PgTable::new("document", "1id").is_err());
        assert!(PgTables::new("grants", "tuples\"").is_err());
        assert!(PgTables::new("themis_grants", "themis_tuples").is_ok());
    }

    #[test]
    fn values_are_bound_never_spliced() {
        let hostile = "x'; DROP TABLE documents; --";
        let expr = Expr::And(vec![
            Expr::AnchorIn {
                kind: "project".into(),
                ids: BTreeSet::from([hostile.to_string()]),
            },
            Expr::AttrEq {
                attr: "owner".into(),
                value: hostile.into(),
            },
            Expr::Within(Anchor::new("org", hostile)),
        ]);
        let (sql, params) = to_where(&expr, &table(), 3).unwrap();
        assert!(!sql.contains("DROP"));
        assert!(!sql.contains('\''));
        assert_eq!(
            sql,
            "((\"project_id\" = ANY($3::text[])) IS TRUE) AND ((\"owner_id\" = $4) IS TRUE) AND ((\"org_id\" = $5) IS TRUE)"
        );
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn unmapped_kinds_and_attributes_are_errors_not_false() {
        assert!(matches!(
            to_where(&Expr::not(Expr::Within(Anchor::new("team", "t1"))), &table(), 1),
            Err(PgQueryError::UnmappedKind(kind)) if kind == "team"
        ));
        assert!(matches!(
            to_where(&Expr::Residual(0), &table(), 1),
            Err(PgQueryError::Residual)
        ));
        let attr = Expr::AttrEq {
            attr: "status".into(),
            value: "draft".into(),
        };
        assert!(matches!(
            to_where(&attr, &table(), 1),
            Err(PgQueryError::UnmappedAttribute(name)) if name == "status"
        ));
    }

    /// F1: a grant on every project (`TargetSelector::kind`) is the commonest shape; it must
    /// translate, as "the path has a step of this kind".
    #[test]
    fn a_step_with_no_id_is_a_kind_predicate_not_an_error() {
        let (sql, params) = to_where(&Expr::Within(Anchor::kind_only("project")), &table(), 1).unwrap();
        assert_eq!(sql, "\"project_id\" IS NOT NULL");
        assert!(params.is_empty());
        let on_path = Expr::OnPath(themis::TargetSelector::kind("project"));
        assert_eq!(to_where(&on_path, &table(), 1).unwrap().0, "\"project_id\" IS NOT NULL");
        // The listed kind itself is the id column.
        let own = Expr::OnPath(themis::TargetSelector::kind("document"));
        assert_eq!(to_where(&own, &table(), 1).unwrap().0, "\"id\" IS NOT NULL");
        // A kind with no column still fails loudly.
        assert!(matches!(
            to_where(&Expr::OnPath(themis::TargetSelector::kind("team")), &table(), 1),
            Err(PgQueryError::UnmappedKind(_))
        ));
    }

    /// F3: a NULL column never makes an atom NULL, so `NOT` over it holds and a deny elsewhere does
    /// not drop the row.
    #[test]
    fn every_atom_is_total_over_null_columns() {
        let ids = Expr::AnchorIn {
            kind: "project".into(),
            ids: BTreeSet::from(["p1".to_string()]),
        };
        let attr = Expr::AttrEq {
            attr: "owner".into(),
            value: "u1".into(),
        };
        for expr in [ids, attr, Expr::Within(Anchor::new("org", "o1"))] {
            let sql = to_where(&Expr::not(expr), &table(), 1).unwrap().0;
            assert!(sql.starts_with("NOT (("), "{sql}");
            assert!(sql.ends_with(") IS TRUE)"), "{sql}");
        }
    }

    #[test]
    fn table_names_leave_room_for_the_index_suffix() {
        let long = "t".repeat(48);
        assert!(PgTables::new(&long, "themis_tuples").is_err());
        let fits = "t".repeat(47);
        let tables = PgTables::new(&fits, "themis_tuples").unwrap();
        let sql = tables.schema_sql();
        assert!(sql.contains(&format!("\"{fits}_target_kind_idx\"")));
        assert!(PgTable::new("document", "c".repeat(64)).is_err());
    }

    #[test]
    fn global_step_is_always_true_and_empty_sets_are_false() {
        assert_eq!(
            to_where(&Expr::Within(Anchor::global()), &table(), 1).unwrap().0,
            "TRUE"
        );
        let none = Expr::AnchorIn {
            kind: "project".into(),
            ids: BTreeSet::new(),
        };
        assert_eq!(to_where(&none, &table(), 1).unwrap().0, "FALSE");
        assert_eq!(to_where(&Expr::not(Expr::True), &table(), 1).unwrap().0, "NOT (TRUE)");
    }

    #[test]
    fn schema_quotes_both_tables() {
        let sql = PgTables::default().schema_sql();
        assert!(sql.contains("\"themis_grants\""));
        assert!(sql.contains("\"themis_tuples\""));
        assert!(sql.contains("CREATE INDEX IF NOT EXISTS \"themis_grants_permission_idx\""));
    }
}
