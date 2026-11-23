use crate::dsl::error::PrintError;
use crate::dsl::policy::Policy;

pub(crate) fn print(_policy: &Policy) -> Result<String, PrintError> {
    Err(PrintError::Unsupported("blocks"))
}
