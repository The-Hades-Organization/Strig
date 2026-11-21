# Contributing to Themis

**English** · [Português (Brasil)](#contribuindo-com-a-themis)

Thanks for your interest. Issues and pull requests are welcome in English or Brazilian Portuguese.

## Before you start

- For a bug, open an issue with the smallest spec, grants and request that reproduce it, plus the decision you got and the one you expected. `themis-inspect explain` output helps a lot.
- For a new feature or a behavior change, open an issue first so we can agree on the design before you write code.
- Security problems go through [SECURITY.md](SECURITY.md), never through a public issue.

## Development

You need Rust 1.88 or newer. The commands CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --exclude themis-inspect --all-targets -- -D warnings
cargo clippy -p themis-inspect --no-default-features --all-targets -- -D warnings
cargo test --workspace --exclude themis-inspect
cargo test -p themis-inspect --no-default-features
```

The README's [Development](README.md#development) section covers the transports against real Redis and Postgres, the JS bindings and the gpui window.

## Pull requests

- Keep each pull request to one change, with tests for the behavior it adds or fixes.
- A change that can open access where it was closed before (a strategy, an override, condition evaluation) needs a test showing the deny case still denies.
- Update both READMEs (`README.md` and `README.pt-BR.md`) when you change something documented there, and add a line to `CHANGELOG.md` under `Unreleased`.
- Commit messages follow `<type>: <description>` (`feat`, `fix`, `refactor`, `test`, `docs`, `chore`).

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).

---

# Contribuindo com a Themis

Issues e pull requests são bem-vindos em português ou inglês.

- **Bug:** abra uma issue com a menor spec, os grants e o pedido que reproduzem o problema, a decisão que saiu e a esperada. A saída do `themis-inspect explain` ajuda bastante.
- **Funcionalidade nova ou mudança de comportamento:** abra uma issue antes, para combinarmos o desenho antes do código.
- **Segurança:** pelo [SECURITY.md](SECURITY.md), nunca por issue pública.
- **Pull request:** uma mudança por PR, com testes. Mudança que pode abrir acesso antes fechado precisa de teste mostrando que a negação continua negando. Atualize os dois READMEs quando mexer no que eles documentam e acrescente uma linha ao `CHANGELOG.md` em `Unreleased`. Os comandos que o CI roda estão na seção em inglês acima.

Ao contribuir, você concorda que sua contribuição fica sob a [licença MIT](LICENSE).
