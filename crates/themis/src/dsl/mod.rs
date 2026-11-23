//! The Themis policy language: text that compiles to the real types of the crate and serializes
//! to the canonical JSON.
//!
//! Every source declares its syntax on its first significant line, `language blocks`, and holds
//! one syntax only. [`parse`] reads and validates one source; the result is a [`Policy`], the same
//! value whatever the syntax, whose JSON is the source of truth. [`print`] writes a policy back
//! as text, comments included.
//!
//! The feature is pure: no IO, no clock, no async. Reading files lives in the `dsl-fs` feature.
//!
//! ```
//! use themis::dsl::{parse, print, Language};
//!
//! let text = "language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n";
//! let parsed = parse("policy.themis", text).unwrap();
//! assert_eq!(parsed.language, Language::Blocks);
//! assert_eq!(print(&parsed.policy, Language::Blocks).unwrap(), text);
//! ```

mod blocks;
mod blocks_print;
mod build;
mod error;
#[cfg(feature = "dsl-fs")]
pub mod fs;
mod grammar;
mod lex;
mod policy;
mod project;
mod time;
mod validate;

use std::sync::Arc;

use build::Builder;
use grammar::Cursor;

pub use error::{Diagnostic, Diagnostics, Location, PrintError};
pub use policy::{Language, Note, NoteAnchor, NoteOrigin, Origins, Placement, Policy};
pub use project::{Built, MAX_PROJECT_BYTES, MAX_SOURCES, Project};

/// The largest source accepted: input is external and unbounded.
pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// One source read and validated.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Parsed {
    /// The syntax the source declared.
    pub language: Language,
    /// The policy it describes, with its comments in `notes`.
    pub policy: Policy,
    /// Where each element was declared.
    pub origins: Origins,
}

impl Policy {
    /// Checks the policy as a whole, with no source positions.
    ///
    /// # Errors
    /// Every problem found, in the order the policy lists the elements.
    pub fn validate(&self) -> Result<(), Diagnostics> {
        let found = validate::validate(self, None);
        if found.is_empty() {
            Ok(())
        } else {
            Err(Diagnostics::new(found))
        }
    }
}

/// Reads a source and validates it.
///
/// `file` is the name used in positions (`file:line:column`); it is never opened.
///
/// # Errors
/// Every syntax and validation error found, sorted by position.
pub fn parse(file: &str, text: &str) -> Result<Parsed, Diagnostics> {
    let mut parsed = parse_unvalidated(file, text)?;
    let found = validate::validate(&parsed.policy, Some(&parsed.origins));
    if !found.is_empty() {
        return Err(Diagnostics::new(found));
    }
    parsed.policy.notes.shrink_to_fit();
    Ok(parsed)
}

/// Reads a source without validating the policy as a whole: for a [`Project`], which validates the
/// set of sources instead.
pub(crate) fn parse_unvalidated(file: &str, text: &str) -> Result<Parsed, Diagnostics> {
    let file: Arc<str> = Arc::from(file);
    if text.len() > MAX_SOURCE_BYTES {
        let raw = error::Raw::new(
            error::Span {
                line: 1,
                col: 1,
                len: 1,
            },
            format!("the source is larger than {MAX_SOURCE_BYTES} bytes"),
        );
        return Err(Diagnostics::new(vec![raw.locate(&file)]));
    }
    let lexed = lex::lex(text);
    if !lexed.errors.is_empty() {
        let found = lexed.errors.into_iter().map(|raw| raw.locate(&file)).collect();
        return Err(Diagnostics::new(error::capped(found, lexed.hidden)));
    }
    let mut cursor = Cursor::new(lexed.tokens);
    let language = match header(&mut cursor) {
        Ok(found) => found,
        Err(raw) => return Err(Diagnostics::new(vec![raw.locate(&file)])),
    };
    let mut builder = Builder::new(file, language.1);
    builder.open(policy::ids::LANGUAGE, language.0);
    builder.close(cursor.previous_span());
    // `header` refuses the other languages until their syntaxes exist.
    if language.1 == Language::Blocks {
        blocks::parse(&mut cursor, &mut builder);
    }
    let (policy, origins, found) = builder.finish(&lexed.comments);
    if !found.is_empty() {
        return Err(Diagnostics::new(found));
    }
    Ok(Parsed {
        language: language.1,
        policy,
        origins,
    })
}

/// `language <name>`: the first significant token of every source.
fn header(cursor: &mut Cursor) -> error::PResult<(error::Span, Language)> {
    let first = cursor.current();
    let at = first.span;
    if !cursor.eat_word("language") {
        return Err(error::Raw::new(at, "a source starts by declaring its language")
            .hint("write on the first line: language blocks"));
    }
    let word = cursor.word("a language name")?;
    let language: Language = word.v.parse().map_err(|()| {
        error::Raw::new(word.span, format!("unknown language `{}`", word.v))
            .hint("expected one of: blocks, rules, actors")
    })?;
    if language != Language::Blocks {
        return Err(
            error::Raw::new(word.span, format!("the {language} syntax is not available yet"))
                .hint("use: language blocks"),
        );
    }
    Ok((at, language))
}

/// Writes a policy as text in the given syntax, comments back in place.
///
/// # Errors
/// [`PrintError::Unrepresentable`] when the policy holds something the syntax cannot say, and
/// [`PrintError::Unsupported`] for a syntax this build does not have.
pub fn print(policy: &Policy, language: Language) -> Result<String, PrintError> {
    match language {
        Language::Blocks => blocks_print::print(policy),
        other => Err(PrintError::Unsupported(other.name())),
    }
}
