# Strig for VS Code

Language support for [Strig](https://github.com/The-Hades-Organization/Strig) policies (`.strig`, in any of the
three syntaxes): highlighting, diagnostics while you type (also across the files of the folder and for
`*.strig-test.json`), completion, hover, go to definition, format document, conversion between syntaxes, and the
command **Strig: Run policy tests**.

The extension talks to the `strig-lsp` language server and calls `strig test`:

```sh
cargo install --git https://github.com/The-Hades-Organization/Strig strig-lsp --locked
cargo install strig-cli --locked
```

Settings: `strig.server.path` (default `strig-lsp`) and `strig.cli.path` (default `strig`).
