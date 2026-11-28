# Migration guide

What to change in your code when you upgrade, release by release. The newest release comes first. The
[changelog](../CHANGELOG.md) lists every change; this page shows the before, the after and the step for the ones that
need action. The rules for what counts as breaking are in [versioning.md](versioning.md).

## 0.10 → 1.0

The public API is frozen from `1.0.0-rc.1` (see the promise in [versioning.md](versioning.md)). This is the last
window for breaking changes, and it breaks only Rust code that names the types below. The JavaScript package, the
Python, Go and JVM bindings, the JSON protocol, the policy language, the stored data and the audit hash need no edit.

### Rust: growing enums and result structs are `#[non_exhaustive]`

Every public enum that can gain a variant (the error enums such as `EngineError`, `GrantError`, `SpecError`,
`PendingError`, `AuditError` and `QueryError`, and `Condition`, `Operand`, `Reason`, `Rewrite`, `Value` and
`MutationKind` among others) and the structs the library returns (`Decision`, `Explanation`, `WhoCan`, `CheckAnswer`,
`AuditStats`, `Violation`, `Materialized` and similar) can now grow without a major version.

**Before.**

```rust
match builder.build() {
    Ok(engine) => use_it(engine),
    Err(EngineError::UnknownPermission(p)) => reject(p),
}
```

**After.** Add a catch-all arm that fails closed, and `..` when you destructure a result struct.

```rust
match builder.build() {
    Ok(engine) => use_it(engine),
    Err(EngineError::UnknownPermission(p)) => reject(p),
    Err(_) => reject_unknown(),
}
let Decision { effect, .. } = decision;
```

A result struct can no longer be built with a literal outside the crate that defines it: get one from the API that
produces it. Structs you build to feed the library (`Review`, `Resource`, `Anchor`, `Lease`, `Proposal`, `EvalContext`,
`SessionOptions`, `RetryPolicy`, `WindowColumns` and other input records) are unchanged.

`Effect`, `PendingStatus`, `TupleSubject`, `Mutation` and `SubjectMatcher` stay exhaustive on purpose: a store or
caller must handle every variant, so a new one is a major change.

### Added, no action

- `strig::audit::AUDIT_FORMAT` (1) and `strig::dsl::DSL_SCHEMA` (5) are public constants.
- `dsl.run_tests` is in the `__all__` of the Python package.
- CI gates for the public Rust API (`cargo semver-checks`), the `.d.ts` and `.pyi` snapshots and the frozen fixtures.

## 0.10.0

Four changes break, all of them only for Rust code that names these types. The JavaScript package, the Python, Go and
JVM bindings, the JSON protocol, stored requests and records, and the audit hash need no edit. The types below are now
`#[non_exhaustive]` so that a field or variant added later is no longer a breaking change.

### Rust: `AuditAction` is `#[non_exhaustive]` and has `ElevationReview`

**Before.**

```rust
match record.action { AuditAction::Apply => .., AuditAction::Check => .. /* every variant */ }
```

**After.** An exhaustive `match` no longer compiles outside `strig`:

```rust
match record.action { AuditAction::Apply => .., AuditAction::Check => .., _ => .. }
```

**Step.** Add a `_ =>` arm to every `match` on `AuditAction`. `ElevationReview` is only written by
`Elevations::close_review`; in the JSON it is `elevation_review`, so add it to a closed list of `action` values in a
log consumer. Reading, serialising and comparing the values is unchanged. `PendingStore` has a new method, `annotate`,
with a default that refuses, so existing implementations still compile.

### Rust: `PendingRequest`, `Approved` and `AuditRecord` gain `impact` and are `#[non_exhaustive]`

**Before.**

```rust
let req = PendingRequest { id, author, change, status, expires_at, .. };
let AuditRecord { id, action, .. } = record;
```

**After.**

```rust
let req = PendingRequest::new(id, author, change).expiring_at(at).with_impact(impact);
let AuditRecord { id, action, .. } = record;
```

**Step.** Build a `PendingRequest` with `PendingRequest::new(..)` and its builders (`expiring_at`, `with_status`,
`with_impact`, `with_elevation`) instead of a struct literal. `Approved` (field `proposed_impact`) and `AuditRecord`
come from `Approvals` and the auditor, so only code that built them by hand changes. Add `..` to every pattern that
destructures any of the three. Stored requests and records without `impact` still load.

### Rust: `CatalogExport` gains `mutually_exclusive` and `conflicting_actions`; `Impact` gains `separation`

**Before.**

```rust
let export = CatalogExport { permissions, roles, .. /* every field */ };
let CatalogExport { permissions, roles } = export;
```

**After.**

```rust
let export = CatalogExport { permissions, roles, ..CatalogExport::default() };
let CatalogExport { permissions, roles, .. } = export;
```

**Step.** Build it with `CatalogExport { .., ..CatalogExport::default() }` or through `Catalog::export`, and put a `..`
in every pattern that destructures it. JSON and the bindings are unaffected: both fields are optional on read and
omitted when empty.

### Rust: revisions in `strig-sync` and `strig-server` types

`Change` (`strig-sync`), `Snapshot`, `CheckRequest`, `CheckResponse`, `BatchRequest` and `BatchResponse`
(`strig-server`) gain a `revision` (`min_revision` on the two requests). `ServerMessage` and `ClientMessage` gain
variants and fields (`ClientMessage::RefreshAtLeast`, `ServerMessage::Hello.version`,
`ServerMessage::Capabilities.revision`). All of them are now `#[non_exhaustive]`.

**Before.**

```rust
let change = Change { scope, kind, .. };
let req = CheckRequest { subject, permission, resource, env, at };
match message { ServerMessage::Hello { .. } => .., ServerMessage::Change(c) => .. /* every variant */ }
```

**After.**

```rust
let change = Change::new(kind, scope).with_revision(rev);
let req = CheckRequest::new(subject, permission, resource).with_env(env).at(at).with_min_revision(rev);
match message { ServerMessage::Hello { .. } => .., ServerMessage::Change(c) => .., _ => .. }
```

**Step.** Build values with the constructors and builders (`Change::new` and `with_revision`, `Snapshot::new` with
`with_revision` and `with_tuples`, `CheckRequest::new` with `with_env`, `at` and `with_min_revision`,
`BatchRequest::new`, `ServerMessage::hello` and `ServerMessage::capabilities` with `with_revision`) instead of struct
literals, add `..` to every pattern that destructures these structs and the two `ServerMessage` variants, and add a
`_` arm to every `match` on the two enums. Responses are built by the server, so only code that built them by hand
changes. The JSON protocol stays additive: every new field is optional and omitted when empty, and a peer that sends
none keeps working.

### Policies with separation of duties export `"schema": 5`

`DSL_SCHEMA` is now 5. A policy that uses `mutually_exclusive`, `conflicting_actions` or the `separation_of_duties`
invariant exports its canonical JSON with `"schema": 5`; a reader of an older schema refuses it instead of ignoring
a rule that denies. A policy without them still exports the schema it did before. Upgrade every reader of the exported
JSON (the JS package, `strig-cli`, other services) before you ship a policy that uses them.

### New, no action

Everything else in 0.10.0 is additive: the language server and VS Code extension, audit proofs (Merkle, RFC 3161),
`why_not`, change impact, `strig diff` and `strig lint`, the Casbin and OpenFGA importers, temporary elevation and
break-glass, separation of duties, recertification campaigns and revisions for reading your own writes.

## 0.9.0

One change breaks, and only for Rust code. The JavaScript package, the JSON spec and stored data need no edit.

### Rust: `Grant`, `PermissionDef`, `Request`, `CatalogError`, `GrantError` and `Verdict` are `#[non_exhaustive]`

Field permissions add `Grant::fields`, `PermissionDef::fields`, `Request::field` and new variants of `CatalogError`,
`GrantError` and `Verdict`. The types are now `#[non_exhaustive]` so that a field or variant added later is no longer
a breaking change.

**Before.**

```rust
let g = Grant { id, effect, subject, permission, target, condition, .. };
match verdict { Verdict::Candidate => .., Verdict::OutOfScope => .. /* every variant */ }
```

**After.** A struct literal and an exhaustive `match` on these types no longer compile outside `strig`:

```rust
let g = Grant::allow(id, subject, permission, target).when(condition);
let r = Request::new(subject, permission, resource).field("email");
match verdict { Verdict::Candidate => .., Verdict::OutOfScope => .., _ => .. }
```

**Step.** Build values with the constructors and builders (`Grant::allow`, `Grant::deny`, `Grant::new` and its chained
methods, `PermissionDef::new` and its builders, `Request::new` with `.field(..)`), and add a `_` arm to every `match`
on `CatalogError`, `GrantError` and `Verdict`. Nothing changes for a policy that does not use fields.

### Policies with fields export `"schema": 4`

`DSL_SCHEMA` is now 4. A policy that uses `fields` exports its canonical JSON with `"schema": 4`; a reader of an older
schema refuses it instead of reading a field-restricted grant as covering the whole resource. A policy without fields
still exports the schema it did before. Upgrade every reader of the exported JSON (the JS package, `strig-cli`, other
services) before you ship a policy with fields.

### New, no action

Everything else in 0.9.0 is additive: ORM adapters (`/prisma`, `/drizzle`, `/kysely`), Envoy External Authorization in
`strig-server` (`envoy` feature, off by default), policy tests and `strig-cli`, the Python package `strig-auth`, the
Go and JVM bindings over `strig-wasi`, and `allowedFields`/`explainFields`/`pickAllowed` in the JS binding.

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

### New, no action: AuthZEN in `strig-server`

`DecisionServer::with_authzen(AuthzenConfig)` is an addition. Without that call the server has no `/access/v1/*` or
`/.well-known/authzen-configuration` route, and `/v1` is unchanged. Call it only if you want to serve the OpenID
AuthZEN Authorization API next to `/v1`.

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

### Rust: `AuditAction::ElevationReview`

**Before.** The last action of the approval flow was `AuditAction::MutationExpire`.

**After.** Temporary elevation (see the README) adds `AuditAction::ElevationReview`, written when someone closes the review of a break-glass elevation. In the JSON it is `elevation_review`. The other steps of an elevation reuse the actions you already have (`mutation_propose`, `mutation_approve`, `mutation_reject`, `grant_remove`, `role_revoke`, ...), with `elevation`, `break_glass`, `justification`, `request_id` and `revoked_by` in the record's metadata.

**Step.** `AuditAction` is now `#[non_exhaustive]`: add a `_ =>` arm where you match it exhaustively outside the crate (an arm for `AuditAction::ElevationReview` is optional), and add `elevation_review` to a closed list of `action` values in a log consumer. Nothing changes for code that never calls `Elevations`. `PendingStore` has a new method, `annotate`, with a default that refuses: implement it in a store of your own before using `Elevations`.

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
