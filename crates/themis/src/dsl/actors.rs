//! The Actors syntax: policy grouped by who acts.

use crate::dsl::build::Builder;
use crate::dsl::error::{PrintError, Raw};
use crate::dsl::grammar::Cursor;
use crate::dsl::policy::Policy;

/// Reads every statement up to the end of the file.
pub(crate) fn parse(cur: &mut Cursor, b: &mut Builder) {
    let span = cur.current().span;
    b.report(Raw::new(span, "the actors syntax is not implemented yet"));
}

/// Writes the policy as an Actors source.
pub(crate) fn print(_policy: &Policy) -> Result<String, PrintError> {
    Err(PrintError::Unsupported("actors"))
}
