//! Compile-time macros for the Themis policy language: a policy that does not validate does not
//! build.
//!
//! [`policy!`] reads a text literal and [`include_policy!`] reads a file. Both compile and
//! validate the source while the caller compiles, through the generic entry point of the core,
//! so every syntax the core knows (Blocks today, Rules and Actors when they land) works without
//! a change here. A DSL error becomes a compile error that carries the diagnostic message, its
//! hint and its position.
//!
//! # Output
//! The expansion is an expression of type `themis::dsl::Policy`. It embeds the canonical JSON of
//! the validated policy and reads it back with `Policy::from_json`. The macro already ran that
//! same read at compile time, so the call cannot fail and the source is never parsed at runtime.
//! A `const` value is not possible: `Policy` owns heap data. The JSON form was chosen over a
//! constructor tree because it is the stable, canonical format of the core and keeps the
//! expansion small.
//!
//! The caller needs the `themis-auth` crate (library name `themis`) with the `dsl` feature as a
//! dependency, since the expansion names `::themis::dsl::Policy`.
//!
//! # Position
//! In `include_policy!` a diagnostic reads `path:line:column: message`. In `policy!` the error
//! points at the literal and the message starts with `policy:line:column`, counted inside the
//! literal text (the first line of the text is line 1).

mod expand;

use proc_macro::TokenStream;

/// Compiles and validates a policy written as a text literal.
///
/// ```ignore
/// let p: themis::dsl::Policy = themis_macros::policy!(r#"
/// language blocks
///
/// target_kinds = [org]
///
/// permission org.read {
///   targets = [org]
/// }
/// "#);
/// ```
///
/// A policy with an error stops the build, with the diagnostic as the message.
#[proc_macro]
pub fn policy(input: TokenStream) -> TokenStream {
    expand::policy(input.into()).into()
}

/// Compiles and validates a policy file, relative to the `CARGO_MANIFEST_DIR` of the caller.
///
/// The file must stay inside that directory. Editing it recompiles the caller. A policy with an
/// error stops the build, with `path:line:column: message` as the message.
///
/// ```ignore
/// let p: themis::dsl::Policy = themis_macros::include_policy!("policies/main.themis");
/// ```
#[proc_macro]
pub fn include_policy(input: TokenStream) -> TokenStream {
    expand::include_policy(input.into()).into()
}
