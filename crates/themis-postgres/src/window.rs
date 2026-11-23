//! SQL predicate that keeps only the grants whose validity window is open at an instant.
//!
//! The grant query belongs to whoever owns the grant table; this module gives it the same rule
//! [`themis::Context::at`] applies in memory, so rows outside the window never leave the database.

use std::fmt;

use crate::quote_ident;

/// Effect value that marks a deny grant. A deny with a window still applies without a `now`.
const DENY_EFFECT: &str = "deny";

/// Names of the columns the predicate reads. Timestamps are milliseconds since the Unix epoch in
/// `bigint` columns, as in the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowColumns {
    pub valid_from: String,
    pub valid_until: String,
    pub effect: String,
}

impl Default for WindowColumns {
    fn default() -> Self {
        Self {
            valid_from: "valid_from".into(),
            valid_until: "valid_until".into(),
            effect: "effect".into(),
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

/// Builds the window filter for a `WHERE` clause. `param_index` is the placeholder number (`$n`)
/// to use for `now`.
///
/// With `now`, a row passes when `valid_from <= now` and `now < valid_until` (null bounds are open).
/// Without it the filter fails closed, like the engine: only rows with no window, and deny rows,
/// pass.
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
        return Ok(WindowPredicate {
            sql: format!("(({from} IS NULL AND {until} IS NULL) OR {effect} = '{DENY_EFFECT}')"),
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
