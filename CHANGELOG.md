# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break the API).

## [Unreleased]

### Added

- `themis`: listing and reverse queries. `Engine::list(ctx, subject, permission, kind)` returns an `AccessFilter` that describes what the subject reaches without enumerating the table: the whole kind (with excluded ids), a set of ids, everything inside some scopes, or nothing. It follows deny, overrides, `implied_by`, role inheritance, scoped roles, ReBAC and the configured strategy. What only the resource can settle (an ABAC condition over a resource attribute, an override that is a closure, a custom strategy) stays in `AccessFilter::residual` to check row by row and is never read as an allow. `AccessFilter::{allows, resolve, resolve_with, expr, shape, is_exact}` evaluate it over in-memory resources or hand a structural `Expr` (over a `PathLayout`) to a database.
- `themis`: `Engine::who_can(permission)`, `who_can_on(permission, resource)`, `access_of(resource)` and `check_for(subject_ref, permission, resource)`. Results name the kind of each party (`SubjectRef`: user, role, principal, userset, ...), so a grant to a role is reported as the role. `check_for` loads the subject through the `SubjectResolver` trait (a closure or `InMemorySubjects`) and returns an `Answer` with the path that decided (`Via`: grant, role, inherited role, relation, override). `QueryContext` carries the indexed sources for these queries.
- `themis`: `GrantIndex` (grants by permission, target kind or subject) and `TupleIndex` (objects of a kind, subjects of an object), implemented for `Vec<Grant>`, `[Grant]`, `(A, B)`, `CapabilitySet` and `InMemoryTuples`. `RelationSchema::objects_with` and `subjects_of` answer the reverse ReBAC questions, usersets included. `GrantSource` and `TupleStore` are unchanged.
- `themis`: `Override::reach` and `Override::subjects` (both with defaults, so existing overrides keep working as opaque residue) let an override say where it decides. `ResourceOwner` and `PermissionHolder` implement them.
- `themis-postgres`: `query` module with the DDL of the grant and tuple tables, the index queries (`grants_by_permission`, `grants_by_target_kind`, `grants_by_subject`, `tuples_of_kind`, `tuples_of_object`) and `filter_where`, which turns an `AccessFilter` into a parameterized `WHERE` with the residue returned apart. Table and column names are validated; values are always bound parameters.
- Benchmark `cargo bench -p themis-auth --bench listing`.
- Release: each `v*` tag now creates the GitHub release with the notes from this file and attaches the N-API modules (Linux x64/arm64, macOS x64/arm64, Windows x64), the WebAssembly package and `SHA256SUMS`.

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
