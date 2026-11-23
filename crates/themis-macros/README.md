# themis-macros

Compile-time macros for the Themis policy language: a policy that does not validate does not build.

```toml
[dependencies]
themis-auth = { version = "0.3", features = ["dsl"] }
themis-macros = "0.3"
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
- `include_policy!` takes a path relative to the `CARGO_MANIFEST_DIR` of the caller. The path must stay inside that
  directory. Editing the file recompiles the caller. An error reads `path:line:column: message`.
- The syntax comes from the `language` line, so every syntax the core supports works without a change here.
- The expansion embeds the canonical JSON of the validated policy and reads it back into a `Policy`. The macro ran
  that read while compiling, so nothing is parsed at runtime.

## Use the crate directly

`themis-auth` does not re-export these macros behind a `macros` feature. The macros run the parser while compiling, so
`themis-macros` depends on `themis-auth`; a re-export would make a package cycle, which Cargo refuses. Add
`themis-macros` to your own `Cargo.toml`, as above.
