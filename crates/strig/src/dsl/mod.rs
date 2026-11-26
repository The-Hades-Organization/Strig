//! The Strig policy language: text that compiles to the real types of the crate and serializes
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
//! use strig::dsl::{parse, print, Language};
//!
//! let text = "language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n";
//! let parsed = parse("policy.strig", text).unwrap();
//! assert_eq!(parsed.language, Language::Blocks);
//! assert_eq!(print(&parsed.policy, Language::Blocks).unwrap(), text);
//! ```

mod actors;
mod blocks;
mod blocks_print;
mod build;
mod convert;
mod error;
mod format;
#[cfg(feature = "dsl-fs")]
pub mod fs;
mod grammar;
mod lex;
mod policy;
mod project;
mod rules;
mod time;
mod validate;

use std::sync::Arc;

use build::Builder;
use grammar::Cursor;

pub use convert::{ConvertError, convert};
pub use error::{Diagnostic, Diagnostics, Location, PrintError};
pub use format::{FormatError, format, is_formatted};
pub use policy::{Language, Note, NoteAnchor, NoteOrigin, Origins, Placement, Policy};
pub use project::{Built, MAX_PROJECT_BYTES, MAX_SOURCES, Project};

/// The largest source accepted: input is external and unbounded.
pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Support for `strig-macros`; not part of the public API.
#[doc(hidden)]
pub mod __macro_support {
    /// The version of the canonical JSON that `Policy::from_json` reads. `strig-macros` embeds
    /// the JSON it wrote and asserts, in the caller's build, that this is the number it was
    /// built against. Bump it with any change to that JSON that an older reader cannot take, and
    /// bump the same number in `strig-macros`.
    ///
    /// 3: the `tz` of `time_between` and `weekday_in`. A document that uses one is written with a
    /// top-level `"schema": 3`, which a reader of schema 2 refuses as an unknown field instead of
    /// reading the window in UTC; a document without `tz` carries no `schema` and stays readable by
    /// schema 2. This reader takes both.
    ///
    /// 2: the conditions `starts_with`, `ends_with`, `contains`, `any_in`, `all_in`, `ip_in`,
    /// `time_between` and `weekday_in`. A reader of schema 1 does not know those `op` values
    /// and fails on a policy that uses one.
    pub const DSL_SCHEMA: u32 = 3;
}

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
    // The column each line starts at, for telling comments indented under an element.
    let indents: std::collections::HashMap<u32, u32> = lexed
        .tokens
        .iter()
        .filter(|t| t.bol)
        .map(|t| (t.span.line, t.span.col))
        .collect();
    let mut cursor = Cursor::new(lexed.tokens);
    let language = match header(&mut cursor) {
        Ok(found) => found,
        Err(raw) => return Err(Diagnostics::new(vec![raw.locate(&file)])),
    };
    let mut builder = Builder::new(file, language.1);
    builder.open(policy::ids::LANGUAGE, language.0);
    builder.close(cursor.previous_span());
    if language.1 != Language::Blocks {
        check_indentation(text, &mut builder);
    }
    match language.1 {
        Language::Blocks => blocks::parse(&mut cursor, &mut builder),
        Language::Rules => rules::parse(&mut cursor, &mut builder),
        Language::Actors => actors::parse(&mut cursor, &mut builder),
    }
    let (policy, origins, found) = builder.finish(&lexed.comments, &indents);
    if !found.is_empty() {
        return Err(Diagnostics::new(found));
    }
    Ok(Parsed {
        language: language.1,
        policy,
        origins,
    })
}

/// In Rules and Actors the indentation says what continues or belongs to what, so it is made of
/// spaces: a tab or a no-break space would count as one column and read as something else.
fn check_indentation(text: &str, builder: &mut Builder) {
    for (at, line) in text.lines().enumerate() {
        let lead = line.chars().take_while(|c| c.is_whitespace()).count();
        if lead == line.chars().count() {
            continue;
        }
        let Some(bad) = line.chars().take(lead).position(|c| c != ' ') else {
            continue;
        };
        let place = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        builder.report(
            error::Raw::new(
                error::Span {
                    line: place(at.saturating_add(1)),
                    col: place(bad.saturating_add(1)),
                    len: 1,
                },
                "the indentation has a tab or another space character",
            )
            .hint("indent with spaces only"),
        );
    }
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
        Language::Rules => rules::print(policy),
        Language::Actors => actors::print(policy),
    }
}
