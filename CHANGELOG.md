# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break the API).

## [Unreleased]

### Added

- `exclusive` feature (off by default): exclusive ownership of a resource with priority, preemption and a time limit. `ExclusiveRegistry` keeps one `Lease` per `ObjectRef` behind the `ExclusiveStore` trait (`MemoryExclusiveStore` included) and offers `acquire`, `release`, `renew`, `holder` and `expire`; time is a `now` parameter in milliseconds, so it stays free of clocks and IO and builds for WebAssembly. `acquire_checked` asks the engine for the ownership permission and, to take the resource from a lower-priority holder, for the preemption permission (names configurable through `ExclusivePermissions`, defaults `exclusive.hold` and `exclusive.preempt`). Equal priority never preempts, and the result carries the previous lease so the application can notify its holder. `with_max_ttl` caps lease lifetimes, and a holder raising its own priority needs the preemption permission too. `priority_from_attr` reads a priority from a subject attribute.
- Audit: with `audit` and `exclusive` on, acquisitions, preemptions, refused claims, releases and expirations are recorded through `Auditor::exclusive`, using the new actions `exclusive_acquire`, `exclusive_preempt`, `exclusive_release` and `exclusive_expire`. Existing records keep their format.
- `themis`: validity windows. `Grant` and `RoleAssignment` take optional `valid_from` and `valid_until` (milliseconds since the Unix epoch, `valid_until` exclusive), with builders `valid_from`, `valid_until` and `valid_between`; JSON without the fields stays valid. A window with `valid_until <= valid_from` is refused (`Validity::between`, `try_valid_between`, `RoleAssignment::check_window` and `GrantError::InvalidWindow` in `validate_grant`). `Context::at(now)` makes a grant or role outside its window not exist for decisions, `explain` (`Verdict::OutsideWindow`) and capabilities. Governance does not take a `now` yet: it builds its context without one, so an allow or role with a window is ignored there (fail closed) until a follow-up passes the instant in. Without a `now` the engine fails closed: an allow with a window is ignored and a deny with a window applies. New: `Subject::roles_at`, `next_boundary` (also `CapabilitySet::next_boundary`) with the next start or end among the grants and roles seen, for whoever keeps a cache. `Context::at` and the ABAC `env.now` are separate inputs; feed both from the same instant.
- `themis-sync`: the capability cache cuts its TTL at the next validity boundary and checks the boundary against the wall clock on every read, so it never serves a capability past its `valid_until`, even after a clock step or a suspend. `Hub::schedule_expiry` delivers a local `Change::expiry` at the boundary, and a session schedules one after each push, so affected sessions recompute and receive the new capabilities with no write. The notice names the subject (`Change::expiry`); a session without an id waits for its own boundary and wakes no other session, and `Change::expiry_for_everyone` is explicit. Pending notices are cancelled when the last session that asked for them closes, and a boundary scheduled again right after it fired backs off. Only sessions opened with a `provider` schedule anything; without one the client reloads on its own. `EngineProvider::with_clock` replaces the system clock; `CapabilityProvider::now_ms` and `CapabilityProvider::evaluate` (the set plus the instant and next boundary it was computed for, which also covers grants that start later) have defaults.
- `themis-postgres`: `window_predicate` builds the parameterised SQL filter that mirrors `Context::at` (`valid_from` inclusive, `valid_until` exclusive; without `now`, only rows with no window and rows not known to be an allow, so an unknown or `NULL` effect never drops a deny; `WindowColumns::allow_effect` names the allow value). `candidate_predicate` is the filter for the loader behind `EngineProvider`: it keeps grants that start later so the scheduler sees their start.
- Release: each `v*` tag now creates the GitHub release with the notes from this file and attaches the N-API modules (Linux x64/arm64, macOS x64/arm64, Windows x64), the WebAssembly package and `SHA256SUMS`.
- `themis`: permission prerequisites. `PermissionDef::depends_on` (the opposite of `implied_by`): an `allow` of X only stands when every transitive prerequisite is also allowed on the same resource, otherwise the decision is a deny with `Reason::MissingPrerequisite` and `Explanation::prerequisites` shows each step. The catalog build refuses an unknown prerequisite (`CatalogError::UnknownPrerequisite`), a cycle (`PrerequisiteCycle`) and a prerequisite that no grant could ever reach (`UnreachablePrerequisite`). New invariant `Prerequisites` (`InvariantSpec::Prerequisites`) refuses a change that would leave a subject with X and without Y, including an `Add` of a deny on a prerequisite.
- `themis`: first-class permission attributes, exported in `CatalogExport`: `non_delegable`, `management_only` and `override_only`, with the invariants `NonDelegable` (only whoever holds a configured management permission grants it), `ManagementOnly` (only to the declared management roles) and, for `override_only`, `GrantError::OverrideOnly` in catalog conformance plus `Verdict::OverrideOnly` (the grant is ignored by the decision). All have an `InvariantSpec` variant.
- `themis`: `NoEscalation` (`InvariantSpec::NoEscalation`): the actor only grants a permission, or assigns a role, where they hold everything they hand out, including the implied permissions and the grant's condition, with an optional `Bypass` permission. Removing a deny and revoking a role that carries one count as handing out what the deny blocked.
- `themis`: `NoLockout::with_reserve` (`reserve` in the spec): the violation carries `Violation::suggestion`, a `Suggestion` (subject id and role only) naming the role assignment that would fix the lockout. `Governance` fills it in only when `Invariant::remedy` passes every invariant with the same actor. Nothing is applied; `AuditRecord::suggestions` records it.
- `themis`: `template` module. `RoleTemplate` (id, version, model grants) materializes into ordinary grants with the provenance (`template`, `template_version`) in the change metadata, with no live link to the template; `Materialized::apply` sends each grant through `Governance`. `Materialized::ordered` sorts the grants by number of prerequisites, and `apply` simulates the whole batch before auditing it, so a refused batch leaves only the refusal in the trail.

### Changed

- **Breaking** (`themis`): `Violation` gains the `suggestion` field (build it with `Violation::new`). `Reason`, `Verdict`, `GrantError`, `CatalogError` and `InvariantSpec` (`Prerequisites`, `NonDelegable`, `ManagementOnly`, `NoEscalation`) gain variants, and `Explanation`, `AuditRecord`, `PermissionDef` and `InvariantSpec::NoLockout` gain fields: match with a wildcard arm and use the builders so new fields do not break the code. Migration: add the wildcard arm, or handle the new variants.
- **Breaking** (`themis`): `CatalogExport` gains `dependsOn`, `nonDelegable`, `managementOnly` and `overrideOnly`. A consumer that ignores unknown fields loses these restrictions; read them before enforcing anything client-side.
- `themis`: `Engine::decide_without_overrides` now enforces prerequisites. It only changes the result for catalogs that use `depends_on`.
- `themis-node`: the TypeScript typings follow the new `Reason`, `Verdict`, `Suggestion` and `prerequisites`.
- **Breaking:** `AuditAction` has four new variants, present even when the `exclusive` feature is off. Code that matches it exhaustively needs arms for them (or a wildcard arm).
- `themis`: `Subject::roles_for` now returns only role assignments without a window (it calls `roles_at` with no instant), so code that lists a subject's roles for display stops seeing the temporary ones; use `roles_at` with an instant to include them.
- `themis-sync`: `CapabilityCache::insert` and `insert_at` do not store a set that has a grant already out of its window, and `Change::expiry` takes a subject (`Change::expiry_for_everyone` for the notice to all).
- **Breaking** (`themis`): `Grant` and `RoleAssignment` gain public fields, so struct literals must add `..` or move to the constructors (`RoleAssignment::new`, `RoleAssignment::in_scope`); `Verdict` gains `OutsideWindow` and `GrantError` gains `InvalidWindow`, so exhaustive matches need the new arm; `Context` gains a `now` field set through `Context::at`.

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

[Unreleased]: https://github.com/The-Hades-Organization/Themis/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/The-Hades-Organization/Themis/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/The-Hades-Organization/Themis/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/The-Hades-Organization/Themis/releases/tag/v0.2.0
