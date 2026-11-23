//! Positioned diagnostics: every error of the language says `file:line:column`, what is wrong and,
//! when there is one, how to fix it.

use std::fmt;
use std::sync::Arc;

/// A place in a source: 1-based line and column (counted in characters) and the length of the
/// offending text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct Location {
    pub file: Arc<str>,
    pub line: u32,
    pub column: u32,
    pub len: u32,
}

impl Location {
    pub fn new(file: impl Into<Arc<str>>, line: u32, column: u32, len: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column,
            len,
        }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

/// One error, with the place it points at. A policy that did not come from text (loaded from
/// JSON) has no location.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Diagnostic {
    pub location: Option<Location>,
    pub message: String,
    pub hint: Option<String>,
    /// The other side of a conflict: where the clashing declaration lives.
    pub related: Option<Location>,
}

impl Diagnostic {
    pub fn new(location: Option<Location>, message: impl Into<String>) -> Self {
        Self {
            location,
            message: message.into(),
            hint: None,
            related: None,
        }
    }

    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    #[must_use]
    pub fn with_related(mut self, related: Option<Location>) -> Self {
        self.related = related;
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.location {
            Some(at) => write!(f, "{at}: {}", self.message)?,
            None => f.write_str(&self.message)?,
        }
        if let Some(other) = &self.related {
            write!(f, " (also at {other})")?;
        }
        if let Some(hint) = &self.hint {
            write!(f, "\n  hint: {hint}")?;
        }
        Ok(())
    }
}

/// All the errors found in one pass, in source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostics(Vec<Diagnostic>);

impl Diagnostics {
    pub fn new(items: Vec<Diagnostic>) -> Self {
        Self(items)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Diagnostic> {
        self.0.iter()
    }

    pub fn first(&self) -> Option<&Diagnostic> {
        self.0.first()
    }

    pub fn into_vec(self) -> Vec<Diagnostic> {
        self.0
    }
}

impl IntoIterator for Diagnostics {
    type Item = Diagnostic;
    type IntoIter = std::vec::IntoIter<Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Diagnostics {
    type Item = &'a Diagnostic;
    type IntoIter = std::slice::Iter<'a, Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, item) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{item}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Diagnostics {}

/// A policy that the printer cannot write in the chosen syntax.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PrintError {
    /// The policy carries something the syntax has no way to express (a resource with attributes,
    /// a non-finite number, a role window on a reserve).
    #[error("cannot print {what}: {reason}")]
    Unrepresentable { what: String, reason: String },
    /// The syntax is declared by the language but not available in this build.
    #[error("the {0} syntax is not available yet")]
    Unsupported(&'static str),
}

/// A source range inside one file, before the file name is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Span {
    pub line: u32,
    pub col: u32,
    pub len: u32,
}

/// An error raised while reading, before the file name is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Raw {
    pub span: Span,
    pub message: String,
    pub hint: Option<String>,
}

impl Raw {
    pub fn new(span: Span, message: impl Into<String>) -> Self {
        Self {
            span,
            message: message.into(),
            hint: None,
        }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn locate(self, file: &Arc<str>) -> Diagnostic {
        Diagnostic {
            location: Some(Location {
                file: Arc::clone(file),
                line: self.span.line,
                column: self.span.col,
                len: self.span.len.max(1),
            }),
            message: self.message,
            hint: self.hint,
            related: None,
        }
    }
}

pub(crate) type PResult<T> = Result<T, Raw>;
