//! The formatter: a source is read and written back in the canonical layout of its own syntax.

use crate::dsl::error::{Diagnostics, PrintError};
use crate::dsl::{parse, print};

/// Why a source could not be formatted.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum FormatError {
    /// The source does not compile; the diagnostics carry `file:line:column`.
    Parse(Diagnostics),
    /// The printer could not write the policy back in the syntax the source declared.
    Print(PrintError),
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::Parse(found) => write!(f, "{found}"),
            FormatError::Print(err) => write!(f, "the source cannot be written back: {err}"),
        }
    }
}

impl std::error::Error for FormatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FormatError::Parse(found) => Some(found),
            FormatError::Print(err) => Some(err),
        }
    }
}

/// Rewrites a source in the canonical layout of the syntax its `language` line declares.
///
/// Comments are kept and the order is the one `print` guarantees. Formatting the result again
/// gives the same text. `file` is the name used in error positions; it is never opened.
///
/// # Errors
/// [`FormatError::Parse`] with the positioned diagnostics when the source does not compile,
/// [`FormatError::Print`] when the policy cannot be written back.
pub fn format(file: &str, text: &str) -> Result<String, FormatError> {
    let parsed = parse(file, text).map_err(FormatError::Parse)?;
    print(&parsed.policy, parsed.language).map_err(FormatError::Print)
}

/// Whether a source is already in the canonical layout, without keeping the rewritten text.
///
/// # Errors
/// The same as [`format`].
pub fn is_formatted(file: &str, text: &str) -> Result<bool, FormatError> {
    Ok(format(file, text)? == text)
}
