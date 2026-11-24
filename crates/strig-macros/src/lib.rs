//! Compile-time macros for the Strig policy language: a policy that does not validate does not
//! build.
//!
//! [`policy!`] reads a text literal and [`include_policy!`] reads a file. Both compile and
//! validate the source while the caller compiles, through the generic entry point of the core,
//! so every syntax the core knows (Blocks today, Rules and Actors when they land) works without
//! a change here. A DSL error becomes a compile error that carries the diagnostic message, its
//! hint and its position.
//!
//! # Output
//! The expansion is an expression of type `strig::dsl::Policy`. It embeds the compact canonical
//! JSON of the validated policy and reads it back with `Policy::from_json`. The macro ran that
//! same read at compile time, so the DSL is never parsed at runtime; the JSON is, on every
//! evaluation of the expression. A `const` value is not possible, because `Policy` owns heap
//! data. When the policy is used many times, build it once: keep it in a `static` with
//! `std::sync::LazyLock` instead of calling the macro in a hot path.
//!
//! The expansion also asserts, in the caller's build, that the `strig` it names speaks the
//! same JSON schema as the one this crate was built against (`DSL_SCHEMA`). A mismatch, such as
//! `strig-macros 0.3` next to `strig 0.4`, is a compile error. That assert is why the
//! `.expect` on the read is unreachable. This crate depends on `strig` with `=`, so use the
//! same version of both.
//!
//! The caller needs the `strig` crate with the `dsl` feature as a
//! dependency, since the expansion names `::strig::dsl::Policy`. A caller that forgets the
//! feature gets `could not find dsl in strig`. This crate turns `dsl` on in its own copy of
//! `strig`; with resolver 1 or 2 that unifies into the caller's, with resolver 3 it does
//! not, so do not rely on it.
//!
//! # Position
//! In `include_policy!` a diagnostic reads `path:line:column: message`. In `policy!` the error
//! points at the whole literal (the compiler gives a proc macro no sub-span on stable) and the
//! message starts with `policy:line:column`, counted inside the text. Line 1 is the first line of
//! the text. In a raw string (`r#"..."#`) the lines from the second on, and their columns, match
//! the file once the line where the literal opens is added. In an ordinary literal the text is
//! after escapes (`\n`, a `\` at the end of a line), so write long policies as raw strings or use
//! `include_policy!`.

mod expand;

use proc_macro::TokenStream;

/// Compiles and validates a policy written as a text literal.
///
/// ```ignore
/// let p: strig::dsl::Policy = strig_macros::policy!(r#"
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
/// The file must stay inside that directory, so a policy shared by several crates of a workspace
/// is copied into each (or kept in a crate they depend on). Paths through `target/` or a hidden
/// component (`.env`) are refused, as are directories, files over 4 MiB and files that are not
/// UTF-8. The path as written is tracked, so editing the file, or retargeting a symlink,
/// recompiles the caller. A policy with an error stops the build, with `path:line:column:
/// message` as the message.
///
/// The path is checked, then the file is opened once and read from that handle. Someone who can
/// swap files in the crate directory during the build could still race the check; they can
/// already run code in the build (`build.rs`), so this is not a boundary.
///
/// ```ignore
/// let p: strig::dsl::Policy = strig_macros::include_policy!("policies/main.strig");
/// ```
#[proc_macro]
pub fn include_policy(input: TokenStream) -> TokenStream {
    expand::include_policy(input.into()).into()
}
