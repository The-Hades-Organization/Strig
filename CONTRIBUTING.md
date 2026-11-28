# Contributing to Strig

**English** · [Português (Brasil)](#contribuindo-com-a-strig)

Thanks for your interest. Issues and pull requests are welcome in English or Brazilian Portuguese.

## Before you start

- For a bug, open an issue with the smallest spec, grants and request that reproduce it, plus the decision you got and the one you expected. `strig-inspect explain` output helps a lot.
- For a new feature or a behavior change, open an issue first so we can agree on the design before you write code.
- Security problems go through [SECURITY.md](SECURITY.md), never through a public issue.

## Development

You need Rust 1.88 or newer. The commands CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --exclude strig-inspect --all-targets -- -D warnings
cargo clippy -p strig-inspect --no-default-features --all-targets -- -D warnings
cargo test --workspace --exclude strig-inspect
cargo test -p strig-inspect --no-default-features
```

The README's [Development](README.md#development) section covers the transports against real Redis and Postgres, the JS bindings and the gpui window.

### npm package layout

The published `@the-hades-organization/strig` holds the JS, the wasm and the loader; the native modules live in one package per platform (`scripts/platforms.json` lists them). The release job builds them with `crates/strig-node/scripts/package-platforms.mjs`, which also pins them as `optionalDependencies` of the main package (the repository's `package.json` does not list them, so `npm ci` needs no unpublished package). A new platform means an entry in `platforms.json`, the matrix in `release.yml` and the switch in `js/src/node.ts`.

### Benchmarks

`cargo bench -p strig --bench engine` (criterion, a dev-dependency only) and `node bench/bench.mjs` in `crates/strig-node/js` run the suite behind [docs/benchmarks.md](docs/benchmarks.md). They are not part of CI; the `benchmarks` workflow can be started by hand. Rerun them and update the page when you change the decision path, and say so in the pull request.

### Fuzzing

`fuzz/` holds `cargo-fuzz` (libFuzzer) targets outside the default workspace: `dsl_parse`, `dsl_format` (idempotent), `dsl_convert` (round trip between the three syntaxes), `spec_json`, `condition_eval`, `decide` (never an allow without a candidate grant), `sync_protocol`, `server_wire` and `audit_chain`. They need the nightly toolchain and `cargo install cargo-fuzz`.

```sh
./fuzz/run.sh dsl_convert 120     # one target for 120 seconds, seeded from fuzz/seeds
```

The seeds in `fuzz/seeds` are versioned; the corpus libFuzzer grows (`fuzz/corpus`), `fuzz/artifacts` and `fuzz/target` are not. A crash is written to `fuzz/artifacts/<target>/`: reproduce it with `cargo +nightly fuzz run <target> <file>`, fix it with a regression test in the ordinary suite, and mention it in the pull request. The `fuzz` workflow runs a short round on pull requests that touch the engine, sync, server or `fuzz/`, and a long one every night, keeping the crash as an artifact.

## Releases

A release is its own pull request, made by a maintainer:

1. Move `Unreleased` in `CHANGELOG.md` to `## [x.y.z] - YYYY-MM-DD` and leave an empty `Unreleased`. Every breaking entry has its before, after and step in [docs/migration.md](docs/migration.md).
2. Set the version in the workspace (`[workspace.package]` and `[workspace.dependencies]` in `Cargo.toml`), in `crates/strig-node/js/package.json` and in `Cargo.lock`. The crates and the npm package share one number, chosen by [docs/versioning.md](docs/versioning.md).
3. After the pull request is merged, tag `vx.y.z` on `main`. The release workflow verifies, builds the native modules and the wasm, generates the SBOMs, creates the GitHub release with the notes from the changelog, publishes the crates in dependency order and the npm packages with provenance.

## Deprecating

Follow the [deprecation policy](docs/versioning.md#deprecation-policy): mark the item `#[deprecated(since, note)]` in Rust, `@deprecated` plus a one-time `process.emitWarning` with a `STRIG_DEPnnn` code in JS, and a warning in the policy language; keep the behaviour; list it under **Deprecated** in the changelog with the replacement and the version where it goes. Removal waits for the next major (before 1.0, at least one minor).

## Pull requests

- Keep each pull request to one change, with tests for the behavior it adds or fixes.
- A change that can open access where it was closed before (a strategy, an override, condition evaluation) needs a test showing the deny case still denies.
- A breaking change needs a line under **Breaking** in `CHANGELOG.md` and an entry in [docs/migration.md](docs/migration.md).
- Update both READMEs (`README.md` and `README.pt-BR.md`) when you change something documented there, and add a line to `CHANGELOG.md` under `Unreleased`.
- Commit messages follow `<type>: <description>` (`feat`, `fix`, `refactor`, `test`, `docs`, `chore`).

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).

---

# Contribuindo com a Strig

Issues e pull requests são bem-vindos em português ou inglês.

- **Bug:** abra uma issue com a menor spec, os grants e o pedido que reproduzem o problema, a decisão que saiu e a esperada. A saída do `strig-inspect explain` ajuda bastante.
- **Funcionalidade nova ou mudança de comportamento:** abra uma issue antes, para combinarmos o desenho antes do código.
- **Segurança:** pelo [SECURITY.md](SECURITY.md), nunca por issue pública.
- **Pacote npm:** o pacote principal leva JS, wasm e loader; cada plataforma tem o seu pacote nativo (`crates/strig-node/scripts/platforms.json`), montado e fixado em `optionalDependencies` pela release (`scripts/package-platforms.mjs`). Plataforma nova = entrada no `platforms.json`, na matriz do `release.yml` e no `switch` de `js/src/node.ts`.
- **Release:** uma PR só dela, feita por quem mantém: `Unreleased` do `CHANGELOG.md` vira `## [x.y.z] - AAAA-MM-DD`, a versão sobe no workspace (`Cargo.toml`, `workspace.dependencies`), em `package.json` e no `Cargo.lock`, e depois do merge se cria a tag `vx.y.z` na `main`, que dispara o workflow de release. A versão segue o [docs/versioning.md](docs/versioning.md).
- **Depreciação:** siga a [política](docs/versioning.md#deprecation-policy): `#[deprecated]` em Rust, `@deprecated` mais `process.emitWarning` com código `STRIG_DEPnnn` em JS, aviso na linguagem de políticas; o comportamento se mantém, entra em **Deprecated** no changelog com o substituto, e a remoção espera a próxima major (antes da 1.0, ao menos uma minor).
- **Benchmarks:** `cargo bench -p strig --bench engine` e `node bench/bench.mjs` em `crates/strig-node/js`; ficam fora do CI. Atualize o [docs/benchmarks.md](docs/benchmarks.md) quando mexer no caminho da decisão.
- **Fuzzing:** `./fuzz/run.sh <alvo> [segundos]` (nightly + `cargo install cargo-fuzz`); os alvos e as sementes ficam em `fuzz/`. Um crash vira teste de regressão comum; o workflow `fuzz` roda uma rodada curta por PR e uma longa à noite.
- **Quebra de compatibilidade:** linha em **Breaking** no `CHANGELOG.md` e entrada em [docs/migration.md](docs/migration.md).
- **Pull request:** uma mudança por PR, com testes. Mudança que pode abrir acesso antes fechado precisa de teste mostrando que a negação continua negando. Atualize os dois READMEs quando mexer no que eles documentam e acrescente uma linha ao `CHANGELOG.md` em `Unreleased`. Os comandos que o CI roda estão na seção em inglês acima.

Ao contribuir, você concorda que sua contribuição fica sob a [licença MIT](LICENSE).
