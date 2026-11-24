//! The expansion logic, on `proc_macro2` types so unit tests can run it outside a compiler.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use proc_macro2::{Span, TokenStream};
use quote::quote;
use strig::dsl::__macro_support::DSL_SCHEMA;
use strig::dsl::{Diagnostics, MAX_SOURCE_BYTES, Policy, parse};
use syn::LitStr;

/// The file name used in positions of an inline policy.
const INLINE_NAME: &str = "policy";

/// How the text of an inline policy relates to the source file.
///
/// The compiler gives a proc macro no line or column on stable (`Span::start` is nightly), so a
/// position cannot be shifted to the file. A raw string literal is copied verbatim, so its lines
/// and columns match the source from its second line on, once the line where the literal opens is added; an ordinary
/// literal has escapes and line continuations, so it does not.
#[derive(Clone, Copy)]
struct Origin {
    raw: bool,
}

pub fn policy(input: TokenStream) -> TokenStream {
    match syn::parse2::<LitStr>(input) {
        Ok(lit) => {
            let origin = origin_of(&lit);
            compile(INLINE_NAME, &lit.value(), lit.span(), Some(origin), TokenStream::new())
        }
        Err(error) => error.to_compile_error(),
    }
}

fn origin_of(lit: &LitStr) -> Origin {
    Origin {
        raw: lit.token().to_string().starts_with('r'),
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
    let (logical, canonical) = match resolve(manifest, relative) {
        Ok(found) => found,
        Err(message) => return fail(span, &message),
    };
    let text = match read_limited(&canonical, relative) {
        Ok(text) => text,
        Err(message) => return fail(span, &message),
    };
    // The compiler tracks the path as written (not the canonical one), so retargeting a symlink
    // recompiles the caller. Editing the file does too.
    let Some(tracked) = logical.to_str() else {
        return fail(span, &format!("policy path `{relative}` is not valid UTF-8"));
    };
    let track = quote! { const _: &[u8] = ::core::include_bytes!(#tracked); };
    compile(relative, &text, span, None, track)
}

/// Resolves `relative` against the manifest directory and checks the result stays inside it.
/// Returns the path as written (joined to the manifest) and the canonical path.
fn resolve(manifest: &Path, relative: &str) -> Result<(PathBuf, PathBuf), String> {
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
    refuse_private(path, relative)?;
    let base = manifest
        .canonicalize()
        .map_err(|error| format!("cannot resolve the crate directory: {error}"))?;
    let canonical = base
        .join(path)
        .canonicalize()
        .map_err(|error| format!("cannot read policy file `{relative}`: {error}"))?;
    // A symlink can leave the directory even without `..`; the resolved path is what counts.
    let Ok(inside) = canonical.strip_prefix(&base) else {
        return Err(format!("policy path `{relative}` resolves outside the crate directory"));
    };
    // A symlink can also lead into `target/` or a hidden file; check where it landed.
    refuse_private(inside, relative)?;
    Ok((manifest.join(path), canonical))
}

/// Refuses build output (`target/`) and hidden components (`.env`, `.git/`, `.ssh/`).
fn refuse_private(path: &Path, relative: &str) -> Result<(), String> {
    for component in path.components() {
        if let Component::Normal(name) = component {
            let name = name.to_string_lossy();
            if name == "target" || name.starts_with('.') {
                return Err(format!(
                    "policy path `{relative}` goes through `{name}`; build output and hidden files are not policies"
                ));
            }
        }
    }
    Ok(())
}

/// Opens the file once, checks its kind and size on the open handle, and reads at most the limit.
fn read_limited(path: &Path, relative: &str) -> Result<String, String> {
    let cannot = |error: std::io::Error| format!("cannot read policy file `{relative}`: {error}");
    let file = std::fs::File::open(path).map_err(cannot)?;
    let meta = file.metadata().map_err(cannot)?;
    if !meta.is_file() {
        return Err(format!("policy path `{relative}` is not a regular file"));
    }
    let too_big = || format!("policy file `{relative}` is larger than {MAX_SOURCE_BYTES} bytes");
    if meta.len() > MAX_SOURCE_BYTES as u64 {
        return Err(too_big());
    }
    // The size can change after the check; the cap holds anyway.
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(cannot)?;
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(too_big());
    }
    String::from_utf8(bytes).map_err(|_| format!("policy file `{relative}` is not valid UTF-8"))
}

/// Parses and validates `text`; on success expands to the policy value.
fn compile(name: &str, text: &str, span: Span, origin: Option<Origin>, track: TokenStream) -> TokenStream {
    let parsed = match parse(name, text) {
        Ok(parsed) => parsed,
        Err(found) => return fail(span, &render(&found, origin)),
    };
    // Compact JSON: the literal is embedded in the caller's binary.
    let json = match serde_json::to_string(&parsed.policy) {
        Ok(json) => json,
        Err(error) => return fail(span, &format!("cannot serialize the policy: {error}")),
    };
    // The read the expansion will do at runtime, done now.
    match Policy::from_json(&json) {
        Ok(back) if back.equivalent(&parsed.policy) => {}
        Ok(_) => {
            return fail(
                span,
                "the policy does not survive its canonical JSON; this is a bug in strig",
            );
        }
        Err(error) => return fail(span, &format!("the canonical JSON does not read back: {error}")),
    }
    let schema = DSL_SCHEMA;
    quote! {
        {
            #track
            // A `strig` of another schema than this macro fails the build here, not at runtime.
            const _: () = ::core::assert!(
                ::strig::dsl::__macro_support::DSL_SCHEMA == #schema,
                "strig-macros and strig disagree on the policy JSON schema; use the same version of both",
            );
            // The schema assert above and the read the macro did while compiling make this
            // unreachable.
            ::strig::dsl::Policy::from_json(#json)
                .expect("strig-macros embedded a policy that no longer reads back")
        }
    }
}

/// The message of a compile error. An inline literal gets a note on how to read its positions.
fn render(found: &Diagnostics, origin: Option<Origin>) -> String {
    let mut out = found.to_string();
    if let Some(origin) = origin {
        out.push_str(if origin.raw {
            "\n  note: line 1 is the line where the literal's text starts; from line 2 on, lines and columns (in characters) are those of the file once that line is added"
        } else {
            "\n  note: positions count inside the text after escapes (`\\n`, line continuations); \
             write the policy as a raw string r#\"...\"# to count source lines"
        });
    }
    out
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
        let out = text(&include_from(here, "tests/fixtures/none.strig", Span::call_site()));
        assert!(out.contains("cannot read policy file"), "{out}");
    }

    #[test]
    fn include_error_names_file_line_and_column() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = text(&include_from(here, "tests/fixtures/broken.strig", Span::call_site()));
        assert!(out.contains("tests/fixtures/broken.strig:4:3"), "{out}");
    }

    #[test]
    fn include_tracks_the_file() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = text(&include_from(here, "tests/fixtures/ok.strig", Span::call_site()));
        assert!(out.contains(":: core :: include_bytes"), "{out}");
        assert!(out.contains("tests/fixtures/ok.strig"), "{out}");
    }

    #[test]
    fn an_inline_error_carries_a_note_on_positions() {
        let out = text(&policy(lit(
            "language blocks\n\npermission org.read {\n  bogus = 1\n}\n",
        )));
        assert!(out.contains("raw string"), "{out}");
    }

    #[test]
    fn a_raw_literal_with_many_lines_and_multibyte_text_counts_characters() {
        let source = "language blocks\n\n# café ☃ ñ\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n  bogus = 1\n}\n";
        let out = text(&compile(
            INLINE_NAME,
            source,
            Span::call_site(),
            Some(Origin { raw: true }),
            TokenStream::new(),
        ));
        // `é`, `☃` and `ñ` are not valid outside a string: columns count characters, not bytes.
        assert!(out.contains("policy:3:6"), "{out}");
        assert!(out.contains("policy:3:8"), "{out}");
        assert!(out.contains("policy:3:10"), "{out}");
        assert!(out.contains("line 1 is the line where the literal"), "{out}");
    }

    #[test]
    fn the_expansion_asserts_the_schema_version() {
        let out = text(&policy(lit(BLOCKS)));
        assert!(out.contains("DSL_SCHEMA"), "{out}");
    }

    #[test]
    fn the_expansion_is_compact_json() {
        let out = text(&policy(lit(BLOCKS)));
        assert!(!out.contains("\\n  "), "{out}");
    }

    #[test]
    fn include_rejects_hidden_and_target_paths() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        for bad in [".env", "tests/.hidden/x.strig", "target/x.strig", "a/target/x.strig"] {
            let out = text(&include_from(here, bad, Span::call_site()));
            assert!(out.contains("build output and hidden files"), "{bad}: {out}");
        }
    }

    #[cfg(unix)]
    mod fs {
        use super::*;
        use std::os::unix::fs::symlink;

        /// A fresh directory under the temp dir, removed at the end of the test.
        struct Sandbox(PathBuf);

        impl Sandbox {
            fn new(name: &str) -> Self {
                let dir = std::env::temp_dir().join(format!("strig-macros-{}-{name}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                Self(dir)
            }
        }

        impl Drop for Sandbox {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn run(root: &Path, relative: &str) -> String {
            text(&include_from(root, relative, Span::call_site()))
        }

        #[test]
        fn a_symlink_out_of_the_crate_is_refused() {
            let outside = Sandbox::new("outside");
            let inside = Sandbox::new("inside");
            std::fs::write(outside.0.join("p.strig"), BLOCKS).unwrap();
            symlink(outside.0.join("p.strig"), inside.0.join("p.strig")).unwrap();
            assert!(run(&inside.0, "p.strig").contains("outside the crate directory"));
        }

        #[test]
        fn a_symlink_inside_the_crate_works_and_the_written_path_is_tracked() {
            let root = Sandbox::new("link");
            std::fs::write(root.0.join("v1.strig"), BLOCKS).unwrap();
            symlink(root.0.join("v1.strig"), root.0.join("main.strig")).unwrap();
            let out = run(&root.0, "main.strig");
            assert!(!out.contains("compile_error"), "{out}");
            assert!(out.contains("main.strig"), "{out}");
            assert!(!out.contains("v1.strig"), "{out}");
        }

        #[test]
        fn a_symlink_into_a_hidden_directory_is_refused() {
            let root = Sandbox::new("hidden");
            std::fs::create_dir(root.0.join(".secret")).unwrap();
            std::fs::write(root.0.join(".secret/p.strig"), BLOCKS).unwrap();
            symlink(root.0.join(".secret/p.strig"), root.0.join("p.strig")).unwrap();
            assert!(run(&root.0, "p.strig").contains("hidden files"));
        }

        #[test]
        fn a_directory_is_not_a_policy() {
            let root = Sandbox::new("dir");
            std::fs::create_dir(root.0.join("d")).unwrap();
            assert!(run(&root.0, "d").contains("not a regular file"));
        }

        #[test]
        fn a_file_over_the_limit_is_refused_before_it_is_read() {
            let root = Sandbox::new("big");
            let file = std::fs::File::create(root.0.join("big.strig")).unwrap();
            file.set_len(MAX_SOURCE_BYTES as u64 + 1).unwrap();
            assert!(run(&root.0, "big.strig").contains("is larger than"));
        }

        #[test]
        fn a_file_that_is_not_utf8_is_refused() {
            let root = Sandbox::new("utf8");
            std::fs::write(root.0.join("p.strig"), [0xff, 0xfe, 0x00]).unwrap();
            assert!(run(&root.0, "p.strig").contains("not valid UTF-8"));
        }
    }
}
