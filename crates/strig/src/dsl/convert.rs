//! Conversion between the syntaxes: a source in one is read, then written in another.

use crate::dsl::error::{Diagnostics, PrintError};
use crate::dsl::policy::Language;
use crate::dsl::{parse, print};

/// Why a source could not be converted.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ConvertError {
    /// The input is not a valid source.
    Parse(Diagnostics),
    /// The policy holds something the target syntax cannot say.
    Print(PrintError),
}

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConvertError::Parse(found) => write!(f, "the input does not parse: {found}"),
            ConvertError::Print(err) => write!(f, "the output cannot be written: {err}"),
        }
    }
}

impl std::error::Error for ConvertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConvertError::Parse(found) => Some(found),
            ConvertError::Print(err) => Some(err),
        }
    }
}

/// Reads `text` in whatever syntax it declares and writes it in `to`, comments included.
///
/// # Errors
/// [`ConvertError::Parse`] when the text is not valid, [`ConvertError::Print`] when `to` cannot
/// say something the policy holds.
pub fn convert(text: &str, to: Language) -> Result<String, ConvertError> {
    let parsed = parse("<input>", text).map_err(ConvertError::Parse)?;
    print(&parsed.policy, to).map_err(ConvertError::Print)
}
