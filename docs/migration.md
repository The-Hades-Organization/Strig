# Migration guide

What to change in your code when you upgrade, release by release. The newest release comes first. The
[changelog](../CHANGELOG.md) lists every change; this page shows the before, the after and the step for the ones that
need action. The rules for what counts as breaking are in [versioning.md](versioning.md).

## 0.8.0

Nothing breaks. Every change in 0.8.0 is additive and the defaults behave as in 0.7.0, so upgrading the crates and the
npm package needs no edit to your code, your policies or your stored data.

### New, no action: opt-in features

- **`tracing`** (feature of `strig`, `strig-sync`, `strig-postgres`, `strig-redis` and `strig-server`, off by default):
  spans through `tracing` and metrics through the `metrics` facade. With the feature off nothing is compiled in.
- **`conformance`** (feature of `strig`, off by default, not stable API): `strig::exclusive_conformance::run`, the
  battery to run against your own `ExclusiveStore`.
- **React and Angular** (`@the-hades-organization/strig/react` and `/angular`): `react` (18 or 19) and
  `@angular/core` (17+) are optional peers. Install them only if you import those subpaths.

### New, no action: Postgres and Redis storage

`PgStore`, `PgExclusiveStore` and `RedisExclusiveStore` are additions. `strig-postgres` migration v4 adds the
`<prefix>_exclusive` table; `migrate` is idempotent and additive, so run it as you already do. The `ExclusiveStore`
trait gained `acquire_lease`, `renew_lease`, `release_lease` and `remove_expired` with default bodies, so a store you
implemented keeps compiling and working. `PgQueryError` is `#[non_exhaustive]`; an exhaustive `match` already needs a
`_` arm.

### New, no action: `checkMany` and `explainMany`

`engine.checkMany(ctx, requests)` and `engine.explainMany(ctx, requests)` decide a batch in one call. `check`,
`decide` and `explain` return the same results and throw the same errors as before; they only run faster for
plain-JSON requests.

## 0.7.0

### Rust: `ChainError` has two new variants

**Before.** `match error { Tampered { .. } => .., Broken { .. } => .., Unchained { .. } => .. }` was exhaustive.

**After.** `verify_chain_anchored` can also return `ChainError::AnchorMismatch` (the chain does not start at the known
anchor) and `ChainError::HeadMismatch` (it does not end at the published head). `verify_chain` itself returns the
same three variants as before.

**Step.** Add the two arms, or a `_ =>` arm that refuses the chain. `AuditError` and `AuditRecord` are unchanged, and
so are existing stored records and hashes.

### Rust: `Condition::TimeBetween` and `Condition::WeekdayIn` have a `tz` field

**Before.**

```rust
let c = Condition::TimeBetween { from: "09:00".into(), until: "18:00".into() };
if let Condition::WeekdayIn { days } = &cond { .. }
```

**After.** Both variants carry `tz: Option<String>`:

```rust
let c = Condition::TimeBetween { from: "09:00".into(), until: "18:00".into(), tz: None };
if let Condition::WeekdayIn { days, .. } = &cond { .. }
```

**Step.** Add `tz: None` where you build the variants and `..` where you match them. The constructors
`Condition::time_between` and `Condition::weekday_in` are unchanged, so prefer them; `.in_tz("America/Sao_Paulo")`
sets a zone. The JSON is unchanged: a condition without `tz` serializes exactly as before.

### Rust: new variants in `AuditAction` and `AuditOutcome`

**Before.** `AuditAction` ended at `ExclusiveExpire` and `AuditOutcome` at `Denied`, and an exhaustive `match` on them compiled.

**After.** The approval flow (pending requests, see the README) adds `AuditAction::MutationPropose`, `MutationApprove`,
`MutationReject` and `MutationExpire`, and `AuditOutcome::Pending` (used by `mutation_propose` when a request is kept).

```rust
match record.action {
    // ... the arms you had
    AuditAction::MutationPropose => "change proposed",
    AuditAction::MutationApprove => "change approved",
    AuditAction::MutationReject => "change refused by an approver",
    AuditAction::MutationExpire => "pending change expired",
}
```

**Step.** Add the four action arms and the `Pending` outcome arm, or a `_ =>` arm. Nothing changes for code that never
calls the approval flow: only `Approvals` writes these values. In the JSON they are `mutation_propose`,
`mutation_approve`, `mutation_reject`, `mutation_expire` and `pending`; if a log consumer (a SIEM mapping, a schema)
accepts a closed list of `action` and `outcome` values, add them before you turn the flow on. See
[audit-format.md](audit-format.md#approval-flow-records).

### Rust: `AuditRecord` has a `pending` field

**Before.** `AuditRecord { at, level, actor, .., decision, full_grant, .. }` listed every field.

**After.** There is one more field, `pending: Option<PendingRef>` (the request of an approval-flow record, from the
`standard` level up).

**Step.** Add `pending: None` where you build the struct with a literal, and `..` where you destructure it. Records
you already stored deserialize and hash as before: the field is omitted from the canonical form when unset, so the
hash chain and the test vector do not change.

### New, no action: `MutationKind`, `Approvals` and the JS `/approvals` subpath

`Mutation::kind()` and `MutationKind` (`add`, `remove`, `assign_role`, `revoke_role`), `strig::pending` (`Approvals`,
`ApprovalPolicy`, `PendingStore`, `MemoryPendingStore`) and `@the-hades-organization/strig/approvals` are additions. A
`Governance` that nobody wraps in `Approvals` behaves as before, and a kind with no approval rule applies at once. The
JSON store gains an optional `pending` list; a file without it reads as before and the store version stays 1. If
several processes or versions share one store file, upgrade all of them before the first request is proposed.

### Policies that use `tz` export `"schema": 3`

**Before.** `DSL_SCHEMA` was 2.

**After.** `DSL_SCHEMA` is 3. A policy with no `tz` still exports the JSON it did before; one that uses `tz` exports its
canonical JSON with `"schema": 3`. `Policy::from_json` accepts documents with or without `schema` and refuses one
above 3.

**Step.** Only if you read policy JSON with another reader (a service or tool on an older version): upgrade it before
you start writing `tz`, since a reader of schema 2 refuses the document on purpose rather than reading the window in
UTC. An unknown zone name is now a validation error when the policy loads; fix the name.

### The `tz` default feature adds the time zone database

**Before.** `strig` had `audit` as its only default feature.

**After.** `default = ["audit", "tz"]`. The `tz` feature brings `chrono-tz`: about 0.9 MB more in the `.wasm`
(2.70 MB to 3.58 MB, 657 KB to 785 KB gzipped).

**Step.** If the size matters and you never use `tz`, set `default-features = false, features = ["audit"]`; a `tz`
in a policy is then refused at load.

### npm: one package per platform

**Before.** `@the-hades-organization/strig` bundled the five native modules (about 24 MB unpacked).

**After.** Each platform has its own package, `@the-hades-organization/strig-<platform>`, installed as an optional
dependency (about 8 MB for a typical install). The loader resolves the platform package, then a local build, then the
wasm backend. Linux with musl is served by the wasm backend; `STRIG_BACKEND=native` throws a clear error when there
is no native module.

**Step.** Nothing for most installs. Do not install with `--omit=optional` or `--no-optional` if you want the native
backend, or set `STRIG_BACKEND=wasm` on purpose. A Docker image on Alpine runs on wasm, with the numbers in
[benchmarks.md](benchmarks.md). If you vendored `node_modules` by platform or copied files out of the package, point
them at the platform package.

### `strig-inspect --tab` and terminal text are in English

**Before.** `strig-inspect --tab avaliacao|matriz|auditoria`, with terminal output such as `NEGADO`.

**After.** `strig-inspect --tab evaluation|matrix|audit`, and the output is in English (`DENIED`). The scenario file
in `examples/scenario.json` uses `ben`, `cara`, `visitor` and `invoice-7`. There is no locale selection yet.

**Step.** Change `--tab` in scripts and shortcuts, and any script that matches the old text (`NEGADO` becomes
`DENIED`).

## 0.6.0: Themis becomes Strig

| Before | After |
|---|---|
| `themis-auth` (library `themis`) | `strig` (library `strig`) |
| `themis-sync`, `-redis`, `-postgres`, `-axum`, `-macros`, `-server`, `-inspect` | `strig-sync`, `-redis`, `-postgres`, `-axum`, `-macros`, `-server`, `-inspect` |
| npm `themis-auth` | npm `@the-hades-organization/strig` (since 0.6.1) |
| `use themis::...` | `use strig::...` |
| `*.themis` policy files | `*.strig` |
| `THEMIS_*` environment variables | `STRIG_*` |

**Step.** Rename the dependencies in `Cargo.toml` and `package.json`, the `use` paths, the policy file extension and the
environment variables. Behaviour is the same.

## 0.5.0: `needs` becomes `depends_on`

The Rules and Actors syntaxes write `depends_on <ids>` on a `permission` line where they wrote `needs <ids>`. `needs`
is now an error with the hint `write: depends_on <ids>`. Replace it in existing policy files, in the same position on
the line. The JSON is unchanged. Blocks was already `depends_on`.
