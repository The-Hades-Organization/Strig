# themis-macros

Compile-time macros for the Themis policy language: a policy that does not validate does not build.

```toml
[dependencies]
themis-auth = { version = "0.4", features = ["dsl"] }
themis-macros = "0.4"
```

```rust
use themis_macros::{include_policy, policy};

let inline: themis::dsl::Policy = policy!(r#"
language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
"#);

let from_file: themis::dsl::Policy = include_policy!("policies/main.themis");
```

- `policy!` takes a text literal. An error points at the literal, with `policy:line:column` counted inside the text.
  In a raw string (`r#"..."#`) the lines from the second on match the file once you add the line where the literal
  opens. In an ordinary literal the count is after escapes, so prefer a raw string for anything with several lines.
- `include_policy!` takes a path relative to the `CARGO_MANIFEST_DIR` of the caller. An error reads
  `path:line:column: message`. The file must be inside the crate directory: a policy shared by several crates of a
  workspace has to be copied into each, or live in a crate they depend on. Paths through `target/` or a hidden
  component such as `.env` are refused, and so are directories, files over 4 MiB and files that are not UTF-8. The
  path as written is tracked, so editing the file or retargeting a symlink recompiles the caller.
- The syntax comes from the `language` line, so every syntax the core supports works without a change here.
- The expansion embeds the compact canonical JSON of the validated policy and reads it back into a `Policy`. The DSL
  is never parsed at runtime, but the JSON is, on each evaluation. If you use the policy often, keep it in a static:

  ```rust
  static POLICY: std::sync::LazyLock<themis::dsl::Policy> =
      std::sync::LazyLock::new(|| include_policy!("policies/main.themis"));
  ```

- The expansion asserts that `themis-auth` has the JSON schema this crate was built for, so mixing versions fails
  the build with a message. `themis-macros` pins `themis-auth` with `=`; use the same version of both.
- The caller must enable `dsl` on its own `themis-auth` dependency. This crate enables it on its own copy; with
  resolver 1 or 2 that leaks into the caller's build, with resolver 3 it does not. Without it the build stops with
  `could not find dsl in themis`.

## Tests

The compile-fail cases (`tests/ui`) compare rustc's diagnostics, which change between releases. CI runs them on
stable; the MSRV job only runs a check. When a new stable rustc changes the drawing, regenerate the `.stderr` files
with `TRYBUILD=overwrite cargo test -p themis-macros --test ui` and review the diff: only the formatting around the
message may change, not the message.

## Use the crate directly

`themis-auth` does not re-export these macros behind a `macros` feature. The macros run the parser while compiling, so
`themis-macros` depends on `themis-auth`; a re-export would make a package cycle, which Cargo refuses. Add
`themis-macros` to your own `Cargo.toml`, as above.
