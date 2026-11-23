//! The expansion logic, on `proc_macro2` types so unit tests can run it outside a compiler.

use std::path::{Component, Path, PathBuf};

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::LitStr;
use themis::dsl::{Policy, parse};

/// The file name used in positions of an inline policy.
const INLINE_NAME: &str = "policy";

pub fn policy(input: TokenStream) -> TokenStream {
    match syn::parse2::<LitStr>(input) {
        Ok(lit) => compile(INLINE_NAME, &lit.value(), lit.span(), TokenStream::new()),
        Err(error) => error.to_compile_error(),
    }
}

pub fn include_policy(input: TokenStream) -> TokenStream {
    let lit = match syn::parse2::<LitStr>(input) {
        Ok(lit) => lit,
        Err(error) => return error.to_compile_error(),
    };
    let manifest = match std::env::var_os("CARGO_MANIFEST_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => return fail(lit.span(), "include_policy! needs CARGO_MANIFEST_DIR; build with cargo"),
    };
    include_from(&manifest, &lit.value(), lit.span())
}

fn include_from(manifest: &Path, relative: &str, span: Span) -> TokenStream {
    let full = match resolve(manifest, relative) {
        Ok(full) => full,
        Err(message) => return fail(span, &message),
    };
    let text = match std::fs::read_to_string(&full) {
        Ok(text) => text,
        Err(error) => return fail(span, &format!("cannot read policy file `{relative}`: {error}")),
    };
    // `include_bytes!` makes the compiler track the file: editing it recompiles the caller.
    let tracked = full.to_string_lossy().into_owned();
    let track = quote! { const _: &[u8] = include_bytes!(#tracked); };
    compile(relative, &text, span, track)
}

/// Resolves `relative` against the manifest directory and checks the result stays inside it.
fn resolve(manifest: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(format!(
            "policy path `{relative}` must be relative and stay inside the crate directory"
        ));
    }
    let base = manifest
        .canonicalize()
        .map_err(|error| format!("cannot resolve the crate directory: {error}"))?;
    let full = base
        .join(path)
        .canonicalize()
        .map_err(|error| format!("cannot read policy file `{relative}`: {error}"))?;
    // A symlink can leave the directory even without `..`; the resolved path is what counts.
    if !full.starts_with(&base) {
        return Err(format!("policy path `{relative}` resolves outside the crate directory"));
    }
    Ok(full)
}

/// Parses and validates `text`; on success expands to the policy value.
fn compile(name: &str, text: &str, span: Span, track: TokenStream) -> TokenStream {
    let parsed = match parse(name, text) {
        Ok(parsed) => parsed,
        Err(found) => return fail(span, &found.to_string()),
    };
    let json = match parsed.policy.to_json() {
        Ok(json) => json,
        Err(error) => return fail(span, &format!("cannot serialize the policy: {error}")),
    };
    // The read the expansion will do at runtime, done now: it is why that read cannot fail.
    match Policy::from_json(&json) {
        Ok(back) if back.equivalent(&parsed.policy) => {}
        Ok(_) => {
            return fail(
                span,
                "the policy does not survive its canonical JSON; this is a bug in themis",
            );
        }
        Err(error) => return fail(span, &format!("the canonical JSON does not read back: {error}")),
    }
    quote! {
        {
            #track
            ::themis::dsl::Policy::from_json(#json)
                // The macro read this same JSON while compiling, so this cannot fail.
                .expect("themis-macros embedded a policy that no longer reads back")
        }
    }
}

fn fail(span: Span, message: &str) -> TokenStream {
    syn::Error::new(span, message).to_compile_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCKS: &str = "language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n";

    fn text(tokens: &TokenStream) -> String {
        tokens.to_string()
    }

    fn lit(source: &str) -> TokenStream {
        let l = LitStr::new(source, Span::call_site());
        quote!(#l)
    }

    #[test]
    fn valid_blocks_expands_to_a_json_read() {
        let out = text(&policy(lit(BLOCKS)));
        assert!(out.contains("from_json"), "{out}");
        assert!(!out.contains("compile_error"), "{out}");
    }

    #[test]
    fn a_dsl_error_becomes_a_positioned_compile_error() {
        let out = text(&policy(lit(
            "language blocks\n\npermission org.read {\n  bogus = 1\n}\n",
        )));
        assert!(out.contains("compile_error"), "{out}");
        assert!(out.contains("policy:4:3"), "{out}");
    }

    #[test]
    fn the_diagnostic_hint_reaches_the_message() {
        let out = text(&policy(lit("language nope\n")));
        assert!(out.contains("unknown language"), "{out}");
        assert!(out.contains("hint"), "{out}");
    }

    #[test]
    fn a_missing_language_line_is_an_error() {
        let out = text(&policy(lit("target_kinds = [org]\n")));
        assert!(out.contains("declaring its language"), "{out}");
    }

    #[test]
    fn a_non_literal_argument_is_an_error() {
        let out = text(&policy(quote!(1 + 1)));
        assert!(out.contains("compile_error"), "{out}");
    }

    #[test]
    fn an_empty_policy_is_an_error() {
        let out = text(&policy(lit("")));
        assert!(out.contains("compile_error"), "{out}");
    }

    #[test]
    fn include_rejects_parent_and_absolute_paths() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        for bad in ["../Cargo.toml", "/etc/passwd", "a/../../x"] {
            let out = text(&include_from(here, bad, Span::call_site()));
            assert!(out.contains("must be relative"), "{bad}: {out}");
        }
    }

    #[test]
    fn include_of_a_missing_file_is_an_error() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = text(&include_from(here, "tests/fixtures/none.themis", Span::call_site()));
        assert!(out.contains("cannot read policy file"), "{out}");
    }

    #[test]
    fn include_error_names_file_line_and_column() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = text(&include_from(here, "tests/fixtures/broken.themis", Span::call_site()));
        assert!(out.contains("tests/fixtures/broken.themis:"), "{out}");
    }

    #[test]
    fn include_tracks_the_file() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = text(&include_from(here, "tests/fixtures/ok.themis", Span::call_site()));
        assert!(out.contains("include_bytes"), "{out}");
    }
}
