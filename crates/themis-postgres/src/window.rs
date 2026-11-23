//! SQL predicates for the validity window of grants.
//!
//! The grant query belongs to whoever owns the grant table; this module gives it the same rule
//! [`themis::Context::at`] applies in memory.
//!
//! Two predicates, for two jobs:
//! - [`window_predicate`] keeps the rows whose window is open at an instant: for a query that
//!   answers "what is granted now" and feeds nothing that schedules.
//! - [`candidate_predicate`] keeps every row that has not expired yet, including the ones that start
//!   later: for the loader behind `themis-sync`'s `EngineProvider`, which needs the future starts
//!   to know when to recompute. The engine still applies the window itself.

use std::fmt;

use crate::quote_ident;

/// Names of the columns the predicate reads. Timestamps are milliseconds since the Unix epoch in
/// `bigint` columns, as in the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowColumns {
    pub valid_from: String,
    pub valid_until: String,
    pub effect: String,
    /// Value of the effect column that marks an allow grant (`Effect::Allow` serializes as
    /// `allow`). Any other value, `NULL` included, is treated as possibly a deny.
    pub allow_effect: String,
}

impl Default for WindowColumns {
    fn default() -> Self {
        Self {
            valid_from: "valid_from".into(),
            valid_until: "valid_until".into(),
            effect: "effect".into(),
            allow_effect: "allow".into(),
        }
    }
}

/// The instant does not fit in the `bigint` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstantOutOfRange(pub u64);

impl fmt::Display for InstantOutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "instant {} does not fit in a bigint column", self.0)
    }
}

impl std::error::Error for InstantOutOfRange {}

/// A parenthesised boolean SQL expression and the value to bind to its placeholder, if it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowPredicate {
    pub sql: String,
    /// Bind this as parameter `param_index`. `None` when the predicate has no placeholder.
    pub param: Option<i64>,
}

/// A string literal that reads the same whatever `standard_conforming_strings` is.
fn quote_literal(value: &str) -> String {
    format!("E'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}

/// Builds the window filter for a `WHERE` clause. `param_index` is the placeholder number (`$n`)
/// to use for `now`.
///
/// With `now`, a row passes when `valid_from <= now` and `now < valid_until` (null bounds are open).
/// Without it the filter fails closed, like the engine: only rows with no window, and rows that may
/// be a deny, pass. A row may be a deny unless its effect column equals
/// [`WindowColumns::allow_effect`]: an unknown or `NULL` effect is kept, never dropped, so a
/// table that stores the effect in another spelling cannot make a windowed deny vanish.
///
/// Do not use it to feed `EngineProvider`: a row that starts later is dropped, and so is the start
/// that would trigger the recompute. Use [`candidate_predicate`].
///
/// # Errors
/// [`InstantOutOfRange`] when `now` is above `i64::MAX`.
pub fn window_predicate(
    columns: &WindowColumns,
    param_index: usize,
    now: Option<u64>,
) -> Result<WindowPredicate, InstantOutOfRange> {
    let from = quote_ident(&columns.valid_from);
    let until = quote_ident(&columns.valid_until);
    let Some(now) = now else {
        let effect = quote_ident(&columns.effect);
        let allow = quote_literal(&columns.allow_effect);
        return Ok(WindowPredicate {
            sql: format!("(({from} IS NULL AND {until} IS NULL) OR {effect} IS DISTINCT FROM {allow})"),
            param: None,
        });
    };
    let bound = i64::try_from(now).map_err(|_| InstantOutOfRange(now))?;
    let placeholder = format!("${param_index}::bigint");
    Ok(WindowPredicate {
        sql: format!("(({from} IS NULL OR {from} <= {placeholder}) AND ({until} IS NULL OR {until} > {placeholder}))"),
        param: Some(bound),
    })
}

/// Builds the filter for the grants that a loader hands to a session scheduler: every row that has
/// not expired at `now` (`valid_until` null or after `now`), whether its window is open or opens
/// later. Rows that already expired are dropped, since an expiry needs no notice once evaluated;
/// rows that start later stay, because their start is a moment the session must recompute at.
///
/// Granting is still decided by the engine from the same window, so this keeps no access that
/// [`window_predicate`] would refuse. It has no `NULL`-effect or spelling concern: it never drops
/// a row for its effect.
///
/// # Errors
/// [`InstantOutOfRange`] when `now` is above `i64::MAX`.
pub fn candidate_predicate(
    columns: &WindowColumns,
    param_index: usize,
    now: u64,
) -> Result<WindowPredicate, InstantOutOfRange> {
    let until = quote_ident(&columns.valid_until);
    let bound = i64::try_from(now).map_err(|_| InstantOutOfRange(now))?;
    Ok(WindowPredicate {
        sql: format!("({until} IS NULL OR {until} > ${param_index}::bigint)"),
        param: Some(bound),
    })
}
