# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break the API).

## [Unreleased]

### Added

- Release: each `v*` tag now creates the GitHub release with the notes from this file and attaches the N-API modules (Linux x64/arm64, macOS x64/arm64, Windows x64), the WebAssembly package and `SHA256SUMS`.
- `themis`: permission prerequisites. `PermissionDef::depends_on` (the opposite of `implied_by`): an `allow` of X only stands when every transitive prerequisite is also allowed on the same resource, otherwise the decision is a deny with `Reason::MissingPrerequisite` and `Explanation::prerequisites` shows each step. The catalog build refuses an unknown prerequisite or a cycle. New invariant `Prerequisites` (`InvariantSpec::Prerequisites`) refuses a change that would leave a subject with X and without Y, and `Engine::decide_ignoring_prerequisites`.
- `themis`: first-class permission attributes, exported in `CatalogExport`: `non_delegable`, `management_only` and `override_only`, with the invariants `NonDelegable` (only whoever holds a configured management permission grants it), `ManagementOnly` (only to the declared management roles) and, for `override_only`, `GrantError::OverrideOnly` in catalog conformance plus `Verdict::OverrideOnly` (the grant is ignored by the decision). All have an `InvariantSpec` variant.
- `themis`: `NoEscalation` (`InvariantSpec::NoEscalation`): the actor only grants a permission, or assigns a role, where they hold everything they hand out, with an optional `Bypass` permission.
- `themis`: `NoLockout::with_reserve` (`reserve` in the spec): the violation carries `Violation::suggestion`, the role assignment that would fix the lockout. Nothing is applied; `AuditRecord::suggestions` records it.
- `themis`: `template` module. `RoleTemplate` (id, version, model grants) materializes into ordinary grants with the provenance (`template`, `template_version`) in the change metadata, with no live link to the template; `Materialized::apply` sends each grant through `Governance`.

### Changed

- **Breaking** (`themis`): `Violation` gains the `suggestion` field and no longer implements `Eq` (use `PartialEq`). `Reason`, `Verdict` and `GrantError` gain a variant, and `Explanation`, `AuditRecord`, `PermissionDef` and `InvariantSpec::NoLockout` gain fields: match with a wildcard arm and use the builders so new fields do not break the code.

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
