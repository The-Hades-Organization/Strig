# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break the API), with a Breaking section for changes that need action when upgrading.

## [Unreleased]

### Added

- Conditions (`themis`): `starts_with`, `ends_with` and `contains` on text (`contains` also tests list membership), `any_in` and `all_in` on lists, `ip_in` for an IPv4 or IPv6 address in a CIDR or a list of CIDRs, and `time_between` and `weekday_in` on the decision instant, always in UTC. They are new `op` values, so existing conditions do not change, and there is no regular-expression condition. The time conditions read the instant of `Context::at` (and `QueryContext::at`) through the new `Condition::evaluate_at`; `Condition::evaluate` is unchanged and, without an instant, they cannot be resolved, so an `allow` that uses them does not apply. A listing keeps a condition on a `resource.` attribute as a residue, and `themis-postgres` never turns it into an allow.
- Policy language: the three syntaxes write the new conditions as `a starts_with b`, `env.ip ip_in "10.0.0.0/8"`, `time_between "09:00" "17:30"` and `weekday_in ["mon", "tue"]`. The validator refuses a CIDR, a time of day or a weekday it cannot read, with position and hint. See `docs/dsl.md`.
- `themis-node`: the `Condition` type in `index.d.ts`, in place of `unknown`.
- Formatter for the policy language. `themis::dsl::format` and `is_formatted` (`dsl` feature) rewrite a source in the canonical layout of its syntax, comments kept and idempotent; `themis-inspect fmt [--check] <file|dir>` formats `.themis` files, and `--check` lists the ones that would change and exits with 1; `themis-node` has `format` and `isFormatted`.
- Playground (`playground/`): a page that runs the engine in the browser through the WebAssembly binding. It edits a policy in the three syntaxes, shows the problems with position and hint, answers who can do what, and shows the canonical JSON. `sh playground/build.sh` builds it, and CI checks that the build works.
- Policy language: the validator suggests the closest name when one is a slip away. `unknown permission`, `role X is not declared`, `inherits ... which is not declared` and the catalog's unknown parent, prerequisite and target kind now carry `did you mean `x`?` in the hint, joined to the existing hint where there was one. Candidates are compared in alphabetical order, so a tie gives the same answer every time, and a name with no close candidate gets no suggestion. The message, the order of the errors and the JSON do not change.

### Breaking

- Policy language: the Rules and Actors syntaxes write `depends_on <ids>` on a `permission` line where they wrote `needs <ids>`, so the three syntaxes use the same word as the JSON field. `needs` is now an error with the hint `write: depends_on <ids>`; replace it in existing `.themis` files, in the same position on the line. `DSL_SCHEMA` stays at 2, since the JSON does not change. Blocks was already `depends_on`.

### Changed

- `DSL_SCHEMA` goes from 1 to 2: a reader of schema 1 does not know the new `op` values and fails on a policy that uses one. A policy without them is the same JSON as before. `themis-macros` reads the constant from `themis`, so there is no second number to keep in step.
- Release: the crates job also publishes `themis-macros` and `themis-server`, in dependency order.
- `themis-inspect`: the window takes the visual identity of the playground. It uses the same palette in a light and a dark theme and follows the system appearance, switching when it changes; jade marks structure and allow, clay marks deny, and gold appears only for who, where and numbers. The ruling shows the seal of the playground (open band for allow, closed band with a cross for deny) next to the word, labels are in spaced capitals, and the JSON of an audit record is highlighted with the playground's colours. Read errors use their own tone, so they no longer look like a deny. The ruling header carries the tilted band of the playground, and the capitals use an embedded Roman serif (Cinzel, SIL Open Font License, licence file beside it). No behaviour, layout or command changes.

## [0.4.0] - 2026-11-23

### Added

- Policy language (`themis`, `dsl` feature, off by default; builds for WebAssembly). A policy can be written as text in three syntaxes, Blocks, Rules and Actors, that parse to the same `Policy`. `parse`, `print` and `convert` work on text, and `Project` joins several sources into one policy. Errors carry `file:line:column`, a message and a hint. The guide is in `docs/dsl.md`.
- `themis` (`dsl-fs` feature, not for WebAssembly): `read_file`, `read_dir` (into a `Project`) and `write_file`. `read_dir` refuses a policy file that is a symbolic link, with an error naming it.
- `themis-macros`: new crate with `policy!("...")` and `include_policy!("path.themis")`; a policy that does not validate stops the build, with the message and hint at its position. It is a separate crate, not a `themis-auth` feature; see `docs/dsl.md`.
- Exclusive resources (`themis`, `exclusive` feature, off by default). One holder per resource, with priority, preemption and a time limit, through `ExclusiveRegistry` over an `ExclusiveStore`; `acquire_checked` and `renew_checked` ask the engine for the `exclusive.hold` and `exclusive.preempt` permissions. With `audit` on, every change of holder is recorded through `Auditor::exclusive`.
- Catalog governance (`themis`):
  - `PermissionDef::depends_on`: an `allow` of X stands only when every prerequisite is also allowed on the same resource, otherwise the decision is a deny with `Reason::MissingPrerequisite`. The catalog build refuses an unknown prerequisite, a cycle and a prerequisite that no grant could reach. The `Prerequisites` invariant refuses a change that would leave a subject with X and without Y.
  - `non_delegable`, `management_only` and `override_only`, exported in `CatalogExport`, with the invariants `NonDelegable` and `ManagementOnly`. A grant of an `override_only` permission is ignored by the decision (`Verdict::OverrideOnly`).
  - `NoEscalation`: an actor grants a permission, or assigns a role, only where they hold everything they hand out, including implied permissions and the grant's condition, with an optional bypass permission.
  - `NoLockout::with_reserve`: a refused change that would lock everyone out carries a `Suggestion` naming the role assignment that fixes it. Nothing is applied, and the audit record keeps it.
  - `RoleTemplate` materializes into ordinary grants, with the template id and version in the change metadata and no live link back. `Materialized::apply` sends each grant through `Governance` and simulates the whole batch first.
  - Every new rule has an `InvariantSpec` variant, so it can come from JSON.
- Validity windows (`themis`). `Grant` and `RoleAssignment` take `valid_from` and `valid_until` (milliseconds since the Unix epoch, the end exclusive); `Context::at(now)` and `Governance::at(now)` make what is outside its window not exist. Without an instant the engine fails closed. `next_boundary` gives the next start or end, for whoever keeps a cache.
- `themis-sync`: the capability cache cuts its lifetime at the next validity boundary and never serves a capability past its `valid_until`, even after a clock step or a suspend. `Hub::schedule_expiry` delivers a `Change::expiry` at the boundary, so affected sessions receive the new capabilities with no write. `EngineProvider::with_clock` replaces the system clock.
- `themis-postgres`: `window_predicate` and `candidate_predicate` build the parameterized SQL filter that mirrors `Context::at`. The grant table gains `effect`, `valid_from` and `valid_until` columns with `CHECK`s; a table created before needs them added.
- Listing and reverse queries (`themis`):
  - `Engine::list(ctx, subject, permission, kind)` returns an `AccessFilter`: what the subject reaches, without enumerating the table (the whole kind with exclusions, a set of ids, everything inside some scopes, or nothing). What only the resource can settle stays in `AccessFilter::residual` to check row by row and is never read as an allow.
  - `Engine::who_can`, `who_can_on`, `access_of` and `check_for`. Results name the kind of each party (`SubjectRef`), and `check_for` loads the subject through `SubjectResolver` and answers with the path that decided (`AccessVia`).
  - `QueryContext` carries the sources, the instant (`QueryContext::at`) and `QueryLimits`; a query over a limit fails with `QueryError` instead of answering.
  - `GrantIndex` and `TupleIndex` serve grants and tuples by permission, kind or subject; `RelationSchema::objects_with` and `subjects_of` answer the reverse ReBAC questions. `Override::reach` and `Override::subjects` and `Strategy::native()` let overrides and strategies say where they decide.
  - `themis-postgres` has a `query` module: `PgTables::schema_sql`, `put_grant`, `put_tuple`, the index queries and `filter_where`, which turns an `AccessFilter` into a parameterized `WHERE`. Table and column names are validated and values are always bound.
  - Benchmark: `cargo bench -p themis-auth --bench listing`.
- `themis-server`: new crate that serves decisions over HTTP (axum) and fails closed. Routes: `POST /v1/check`, `/v1/check/batch`, `/v1/list`, `/v1/who` and `/v1/access`, plus `/health/live` and `/health/ready`. `now` is the server clock. A source that is down, a query over its limits, a deadline that passes or any internal error answers 503 with the stable body `{"error":{"code":"...","message":"..."}}`, never an allow. The contract is in `crates/themis-server/API.md`.
- `themis-server`: Rust client behind the `client` feature (on by default), with a timeout per call, a circuit breaker on an injectable clock and batches in one call. A network failure, timeout, 5xx or open circuit is `ClientDecision::Denied`, never an allow.
- `themis-node`: the 0.4.0 engine API in the Node and WebAssembly bindings: `list`, `whoCan`, `whoCanOn`, `accessOf` and `checkFor`, `validFrom` and `validUntil`, `Context.setNow` and `setLimits`, the new invariants, `materialize` and `applyTemplate`, and `Exclusive`. Errors have a stable `code`, and responses use camelCase field names. `index.d.ts` types all of it. `Exclusive.renew` takes `(engine, context, subject, resource, ttlMs, now?)` and checks the hold permission, so a holder who lost it gets `EXCLUSIVE_DENIED`. A refused scalar argument (wrong type, `NaN`, infinity, out of range) throws `INVALID_ARGUMENT`; `INVALID_INPUT` stays for the shape of an object.
- `themis-node`: the policy language in the Node and WebAssembly bindings: `compile`, `print`, `convert` and `loadProject`, plus `loadProjectDir` on the native module only. The policy is the canonical JSON, and errors carry a stable `DSL_*` code and `diagnostics` with file, line, column, message and hint. The guide is in `docs/dsl.md`.
- `themis-auth` (npm): web integrations as subpaths, `themis-auth/express`, `themis-auth/fastify` (`preHandler` and a plugin) and `themis-auth/nestjs` (`@Can(permission, resolver?)` and `ThemisGuard`). You give functions that read the subject, the permission and the resource from the request; nothing is inferred. Each runs in local mode or against a decision server. A deny answers 403, a failing or unreachable service 503, an unidentified caller 401 and an extractor error 500 with no detail; the statuses are configurable and the request never passes otherwise. Express, Fastify and `@nestjs/common` are optional peer dependencies.
- `themis-auth` (npm): `themis-auth/remote`, a client for the decision server with a timeout per call, a circuit breaker, batches and the API's error codes. A network error, timeout, any status other than 200, an unreadable body or an open circuit is a deny.
- Release: each `v*` tag creates the GitHub release with the notes from this file and attaches the Node modules (Linux x64 and arm64, macOS x64 and arm64, Windows x64), the WebAssembly package and `SHA256SUMS`.

### Changed

- `themis`: `Engine::decide_without_overrides` enforces prerequisites; it only changes the result for catalogs that use `depends_on`.
- `themis`: the new query types (`Expr`, `OverrideReach`, `FilterShape`, `FilterResidual`, `AccessVia`, `SubjectRef`, `QueryError`, `QueryContext`, `PgFilter` and the request types) are `#[non_exhaustive]`.

### Breaking

- `themis`: `Violation` gains the `suggestion` field (build it with `Violation::new`). `Reason`, `Verdict`, `GrantError`, `CatalogError`, `InvariantSpec` and `AuditAction` gain variants, and `Explanation`, `AuditRecord`, `PermissionDef` and `InvariantSpec::NoLockout` gain fields. Match with a wildcard arm and use the builders. The four new `AuditAction` variants exist even when `exclusive` is off.
- `themis`: `Grant`, `RoleAssignment`, `Proposal` and `Context` gain public fields (`valid_from`, `valid_until`, `now`). Struct literals must add `..` or move to the constructors (`RoleAssignment::new`, `RoleAssignment::in_scope`).
- `themis`: `Override::subjects` and `SubjectsRequest::holders` return `Result<_, QueryError>`. An override that implements `subjects` returns `Ok(vec)` and propagates the error from `holders` with `?`; one that does not is unaffected.
- `themis`: `CatalogExport` gains `dependsOn`, `nonDelegable`, `managementOnly` and `overrideOnly`. A consumer that ignores unknown fields loses these restrictions: read them before enforcing anything client-side.
- `themis-postgres`: `grants_by_permission`, `grants_by_target_kind` and `grants_by_subject` take `now: Option<u64>`. Pass `None` to keep the fail-closed reading, or the instant of the decision. The crate now depends on `themis`, `serde_json` and `thiserror`.
- `themis`: `Subject::roles_for` returns only role assignments without a window, so code that lists roles for display stops seeing the temporary ones. Use `roles_at` with an instant to include them.
- `themis-sync`: `CapabilityCache::insert` and `insert_at` do not store a set that has a grant already out of its window, and `Change::expiry` takes a subject (`Change::expiry_for_everyone` for the notice to all).

## [0.3.1] - 2026-11-22

### Added

- npm: the `themis-auth` package now ships the README, with images and links pointing to the repository.

### Changed

- Dependencies: `sha2` 0.11, `redis` 1.8 (`themis-redis`, tested against a real Redis 7) and `tokio-tungstenite` 0.29 (`themis-axum`).

## [0.3.0] - 2026-11-21

### Added

- `themis`: governance of role assignments. `Mutation::AssignRole` and `Mutation::RevokeRole` go through `Governance::apply` with the same invariants (unknown role or scope kind, self-management, lockout, `Forbid` on a user) and are audited as `role_assign`/`role_revoke`, including rejected changes with their violations. New: `Mutation::role_change`, `Mutation::subject_after`, `Proposal::subject_after`, `RoleGraph::contains`. `themis-node`: `apply` accepts `assign_role`/`revoke_role` and returns the updated `subject`.
- `themis`: subjects are identified by id alone in `NoSelfManagement`, `NoLockout` and `Proposal::subject_after`. At `forensic`, role-change records carry `before_digest`/`after_digest` of the subject's roles; the audit `object` includes the scope (`member#org:o1@u1`) and an anonymous subject is recorded as `<kind>:<anonymous>`.
- npm package `themis-auth` (was `@the-hades-organization/themis`, never published), with native binaries for Linux, macOS and Windows plus the WebAssembly fallback. Imports use `themis-auth`, `themis-auth/client`, `themis-auth/server` and `themis-auth/protocol`.
- crates.io: `themis-auth`, `themis-sync`, `themis-redis`, `themis-postgres`, `themis-axum`.

### Changed

- `themis`: the crate is published as `themis-auth`. Depend on it with `themis = { package = "themis-auth", version = "0.3" }`; the library keeps the name `themis`, so `use themis::...` does not change. The directory stays `crates/themis`.
- `themis`: `Mutation` has two new variants. A custom `Invariant` that matches `Mutation` exhaustively must handle `AssignRole` and `RevokeRole`; `Proposal::grant` returns `None` for them. `Auditor::grant_mutation` records a role change as `role_assign`/`role_revoke`.

## [0.2.0] - 2026-11-21

### Added

- `themis`: permission catalog with validation, decision engine combining RBAC, ABAC and ReBAC, strategies (`MostSpecific`, `DenyOverrides`, `PermitOverrides`, `FirstApplicable`), overrides, `EngineSpec` in JSON/TOML/YAML.
- `themis`: governance of grant changes with invariants, and auditing at four levels (`minimal`, `standard`, `detailed`, `forensic`) with a hash chain at `forensic`.
- `themis`: `Engine::explain` with the full trace of a decision, and audited access decisions (`Auditor::decide`).
- `themis-sync`, `themis-redis`, `themis-postgres`, `themis-axum`: real-time propagation of grant changes over SSE and WebSocket, with Redis and Postgres transports.
- `themis-node`: JavaScript bindings (N-API for Node and Bun, WebAssembly for the browser), real-time client and server in JS.
- `themis-inspect`: inspector with evaluation trace, grant simulation, access matrix and audit trail reading, as terminal commands and an optional gpui window.

[Unreleased]: https://github.com/The-Hades-Organization/Themis/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/The-Hades-Organization/Themis/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/The-Hades-Organization/Themis/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/The-Hades-Organization/Themis/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/The-Hades-Organization/Themis/releases/tag/v0.2.0
