# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break the API).

## [Unreleased]

### Added

- `themis`: validity windows. `Grant` and `RoleAssignment` take optional `valid_from` and `valid_until` (milliseconds since the Unix epoch, `valid_until` exclusive), with builders `valid_from`, `valid_until` and `valid_between`; JSON without the fields stays valid. A window with `valid_until <= valid_from` is refused (`Validity::between`, `try_valid_between`, `RoleAssignment::check_window` and `GrantError::InvalidWindow` in `validate_grant`). `Context::at(now)` makes a grant or role outside its window not exist for decisions, `explain` (`Verdict::OutsideWindow`) and capabilities. Governance does not take a `now` yet: it builds its context without one, so an allow or role with a window is ignored there (fail closed) until a follow-up passes the instant in. Without a `now` the engine fails closed: an allow with a window is ignored and a deny with a window applies. New: `Subject::roles_at`, `next_boundary` (also `CapabilitySet::next_boundary`) with the next start or end among the grants and roles seen, for whoever keeps a cache. `Context::at` and the ABAC `env.now` are separate inputs; feed both from the same instant.
- `themis-sync`: the capability cache cuts its TTL at the next validity boundary and checks the boundary against the wall clock on every read, so it never serves a capability past its `valid_until`, even after a clock step or a suspend. `Hub::schedule_expiry` delivers a local `Change::expiry` at the boundary, and a session schedules one after each push, so affected sessions recompute and receive the new capabilities with no write. The notice names the subject (`Change::expiry`); a session without an id waits for its own boundary and wakes no other session, and `Change::expiry_for_everyone` is explicit. Pending notices are cancelled when the last session that asked for them closes, and a boundary scheduled again right after it fired backs off. Only sessions opened with a `provider` schedule anything; without one the client reloads on its own. `EngineProvider::with_clock` replaces the system clock; `CapabilityProvider::now_ms` and `CapabilityProvider::evaluate` (the set plus the instant and next boundary it was computed for, which also covers grants that start later) have defaults.
- `themis-postgres`: `window_predicate` builds the parameterised SQL filter that mirrors `Context::at` (`valid_from` inclusive, `valid_until` exclusive; without `now`, only rows with no window and rows not known to be an allow, so an unknown or `NULL` effect never drops a deny; `WindowColumns::allow_effect` names the allow value). `candidate_predicate` is the filter for the loader behind `EngineProvider`: it keeps grants that start later so the scheduler sees their start.
- Release: each `v*` tag now creates the GitHub release with the notes from this file and attaches the N-API modules (Linux x64/arm64, macOS x64/arm64, Windows x64), the WebAssembly package and `SHA256SUMS`.

### Changed

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
