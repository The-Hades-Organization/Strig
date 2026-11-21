# Themis

[![CI](https://github.com/The-Hades-Organization/Themis/actions/workflows/ci.yml/badge.svg)](https://github.com/The-Hades-Organization/Themis/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)

**English** · [Português (Brasil)](README.pt-BR.md)

An authorization library for Rust. A validated permission catalog and a decision engine that combines RBAC, ABAC and ReBAC over the same grants, with governance and auditing of changes, and real-time propagation of those changes all the way to the client.

The core does no IO, does not depend on an async runtime and compiles to WebAssembly. Real time, transports and bindings live in separate crates, each one optional.

> **Status:** pre-1.0. The API can still change between minor versions. The crates and the npm package are not published yet; depend on them through git.

## Crates

| Crate | What it is for | Notable dependencies |
|---|---|---|
| `themis` | Catalog, decision engine, governance, auditing (`audit` feature, on by default), JSON spec | `serde`, `thiserror`; `sha2` and `serde_json` with `audit` |
| `themis-sync` | Change hub, `Transport` trait, framework-independent SSE/WebSocket sessions, capability cache | `tokio` |
| `themis-redis` | `Transport` over Redis pub/sub | `redis` |
| `themis-postgres` | `Transport` over Postgres `LISTEN/NOTIFY`, with the notice sent inside the transaction | `tokio-postgres` |
| `themis-axum` | axum SSE and WebSocket routes over the `themis-sync` sessions | `axum` |
| `themis-inspect` | Inspector: the trace of each decision, grant simulation, access matrix and audit trail reading. Optional gpui window (`gui` feature) and terminal commands | `gpui-pre`, `gpui-component` |
| `themis-node` | JS bindings: native module (N-API) for Node and Bun, WebAssembly for the browser, real-time client and server in JS | `napi` or `wasm-bindgen` |

Depending on it from another crate through git:

```toml
[dependencies]
themis = { git = "https://github.com/The-Hades-Organization/Themis" }
themis-sync = { git = "https://github.com/The-Hades-Organization/Themis" }
```

## Concepts

| Concept | Type | Role |
|---|---|---|
| Catalog | `Catalog`, `PermissionDef` | Dotted keys (`document.invoice.export`), accepted targets, `implied_by`, free-form metadata (`meta`). Validated on construction: malformed key, duplicate, unregistered target, missing parent, cycle, and the application's own rules (`CatalogRule`). Exports and imports JSON. |
| Resource | `Resource`, `Anchor` | Path from the most specific to the broadest (`document:7 → doc_type:invoice → project:42 → org:9`), with an implicit `global` at the end, plus attributes. |
| Subject | `Subject` | Id, roles (optionally scoped), principals (`authenticated`, `anonymous` or your own), attributes. |
| Grant | `Grant` | Subject (`User`, `Role`, `Principal`, `Relation`, `Any`), permission, target, effect, optional scope and condition. |
| Engine | `Engine` | Overrides, collection of the applicable grants, combination by strategy. Returns a `Decision` with the reason, the matched grants and warnings. |
| Governance | `Governance`, `Invariant` | Applies a grant change only if every invariant passes, and records the outcome in the audit trail. |

## Usage

```rust
use themis::*;

let catalog = Catalog::builder()
    .target_kinds(["project", "doc_type", "document"])
    .broad_target("org")
    .permission(PermissionDef::new("document.export").targets(["project", "document"]))
    .permission(
        PermissionDef::new("document.invoice.export")
            .targets(["doc_type", "document"])
            .implied_by(["document.export"]),
    )
    .build()?;

let engine = Engine::builder(catalog)
    .override_with(ResourceOwner::new("owner"))
    .build()?;

let grants = vec![
    Grant::allow("g1", SubjectMatcher::role("member"), "document.export", TargetSelector::kind("org"))
        .scoped(Anchor::new("org", "acme")),
    Grant::deny("g2", SubjectMatcher::Any, "document.invoice.export", TargetSelector::exact("doc_type", "invoice")),
];

let dave = Subject::user("dave").with_role_in("member", Anchor::new("org", "acme"));
let invoice = Resource::new("document", "d1")
    .within("doc_type", "invoice")
    .within("project", "p1")
    .within("org", "acme");

let decision = engine.decide(&Context::new(&grants), &Request::new(&dave, "document.invoice.export", &invoice));
assert!(!decision.is_allowed()); // g2 sits on a more specific step than g1
```

The same configuration can come from JSON, TOML or YAML through `EngineSpec` (catalog, role inheritance, relations, strategy, overrides). `EngineSpec::builder()` returns the `EngineBuilder` so you can add in code what does not serialize, such as condition functions.

Examples: `cargo run -p themis --example documents` (the three models together) and `cargo run -p themis-axum --example server` (real-time server).

## How a decision is made

1. Permission not in the catalog: deny (`Reason::UnknownPermission`).
2. Overrides, in order. The first one that answers decides. `override_except` takes permissions (and the ones they imply) out of an override's reach.
3. Collection: a grant is a candidate when its permission is the requested one or one that implies it, its scope is on the resource path, its target matches a step of the path, its subject matches and its condition is true.
4. The strategy picks the deciding grant. With no candidate, deny.

A condition or relation that cannot be evaluated (missing attribute, engine without a `TupleStore`) never opens access: the `allow` is dropped and the `deny` is applied. The reason goes into `Decision::warnings`.

| Strategy | Rule |
|---|---|
| `MostSpecific` (default) | The most specific step with any grant decides; on that step, `deny` wins. |
| `DenyOverrides` | Any `deny` wins. |
| `PermitOverrides` | Any `allow` wins. |
| `FirstApplicable` | The first grant in source order decides. |

## The three models

**RBAC.** `RoleGraph::builder().inherit("maintainer", "member")` gives `maintainer` the grants of `member`. `Subject::with_role_in(role, anchor)` limits the role to the resources under that step.

**ABAC.** `Grant::when(condition)` with a serializable `Condition`: `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `is_in`, `exists`, `all`, `any`, `not` and `call`. Operands read `subject.*`, `resource.*` and `env.*`. Your own functions are added with `ConditionRegistry::register` and checked by `Engine::validate_grant`.

**ReBAC.** `object#relation@subject` tuples in a `TupleStore` and per-type rules in a `RelationSchema` (`This`, `Computed`, `TupleToUserset`, `Union`, `Intersection`, `Exclusion`), Zanzibar style. `user:*` stands for every user. A grant with `SubjectMatcher::relation("editor")` applies to whoever holds `editor` on the step matched by the target. The search has a maximum depth (`max_relation_depth`, 32 by default) and cuts cycles.

## Governance

```rust
let governance = Governance::new()
    .with(CatalogConformance)
    .with(RequirePermission::new("org.roles.edit", org_resource.clone()))
    .with(NoSelfManagement)
    .with(NoLockout::new(["org.invite"], members, org_resource))
    .with(Forbid::new(SubjectMatcher::principal(AUTHENTICATED), ["project.delete"]))
    .audited(auditor);

let next = governance.apply_with(&engine, &actor, &current, &Mutation::Add(grant), None, &request_meta)?;
// persist `next` only on Ok
```

Add your own rule by implementing `Invariant`. The list can also come from JSON (`InvariantSpec`).

## Auditing

With the `audit` feature, every change that goes through governance becomes an `AuditRecord`, whether applied or refused. ReBAC tuples and role assignments are recorded with `Auditor::tuple_change` and `Auditor::role_change`. If the sink fails to write, governance refuses the change with the `audit` violation: no record, no change.

```rust
let auditor = Arc::new(Auditor::new(AuditLevel::Standard, Arc::new(JsonLinesAudit::new(file))));
```

Built-in sinks: `MemoryAuditLog` and `JsonLinesAudit` (any `io::Write`). A database, queue or SIEM plugs in by implementing `AuditSink`.

### Levels and storage

Each level includes everything from the previous one. Sizes come from the reference record (`audit::reference_record`): a grant with a scope and a two-clause condition, UUID ids, an actor with two roles and three request metadata entries. They are compact JSON bytes in JSON Lines, without compression or indexes. The `estimates_match_reference_records` test fails if the measured size drifts more than 10% from the documented one, and `cargo run -p themis --example audit_storage` measures again.

| Level | What it keeps | Bytes per record | Per 1 million records |
|---|---|---|---|
| `minimal` | When, who, action, object id, outcome | 175 | 175 MB (167 MiB) |
| `standard` | Plus the grant summary (permission, subject, target, effect, scope, whether it has a condition) and the names of the invariants that refused | 388 | 388 MB (370 MiB) |
| `detailed` | Plus the whole grant with its condition, the full actor, the violation messages and the request metadata | 1,097 | 1.10 GB (1,046 MiB) |
| `forensic` | Plus the SHA-256 digest of the grant set before and after, and the hash chain between records | 1,415 | 1.42 GB (1,349 MiB) |

Access decisions can be audited too: `Auditor::decide(&engine, &ctx, &request, &meta)` decides and records, and at the `forensic` level it uses `Engine::explain` and keeps the full trace. Reference record: three grants in the source (one with a condition), a resource with three steps, UUID ids and three metadata entries (`audit::reference_decision_record`, test `decision_estimates_match_reference_records`).

| Level | What it keeps from a decision | Bytes per record | Per 1 million records |
|---|---|---|---|
| `minimal` | When, subject, `permission@resource`, allowed or denied | 285 | 285 MB (272 MiB) |
| `standard` | Plus the reason (override, deciding grant and step, or no grant) and the grants that matched | 669 | 669 MB (638 MiB) |
| `detailed` | Plus the full subject and resource, the warnings and the request metadata; enough to re-evaluate the decision later | 1,239 | 1.24 GB (1,182 MiB) |
| `forensic` | Plus the full trace (`Explanation`) and the hash chain | 3,582 | 3.58 GB (3,416 MiB) |

The forensic trace grows with the number of grants the source returns per decision. `AuditLevel::estimate_decision_bytes(n)` gives the projection in code.

`AuditLevel::estimate_bytes(n)` returns the same projection for changes. In a database, add the row overhead (in Postgres, about 28 bytes between the tuple header and the item pointer) and the indexes you create. Long conditions or large metadata grow `detailed` and `forensic` proportionally.

At the `forensic` level, each record carries the hash of the previous one. `audit::verify_chain` detects an edited or removed record. `Auditor::resume_chain` continues the chain after a restart.

## Real time

```text
grant change ──► Hub::publish ──► local sessions (SSE/WebSocket) and CapabilityCache
                      │
                      └─► Transport (Redis, Postgres, your own) ──► Hub on the other instances
```

The notice (`Change`) states the kind of change and the affected step, without the grants. Receivers reload from the source, so the notice fits any transport. A session watches scopes and, with a `CapabilityProvider`, pushes the capabilities of each affected scope back to the client. Changes that arrive together are recomputed once. When the transport drops and comes back, or a client falls behind, the hub emits `Resync` and everything is reloaded.

```rust
let hub = Hub::builder()
    .transport(RedisTransport::new("redis://127.0.0.1/", "themis:changes")?)
    .build();
let _relay = hub.spawn_relay();

let cache = Arc::new(CapabilityCache::new(Duration::from_secs(30), 10_000));
hub.on_change(cache.clone());
let provider = EngineProvider::new(engine, my_grant_loader).with_cache(cache);
let realtime = themis_axum::Realtime::new(hub).with_provider(Arc::new(provider));
// in the routes: realtime.sse(subject, scopes) or realtime.websocket(upgrade, subject, scopes)
```

Transports:

- **Redis** (`themis-redis`): pub/sub, publishing with automatic reconnection.
- **Postgres** (`themis-postgres`): `LISTEN/NOTIFY`. Calling `themis_postgres::notify(&tx, channel, &change)` inside the transaction that writes the grant makes the notice go out only on commit. TLS through `PgTransport::with_tls`.
- **Your own**: NATS, Kafka or any other broker implements `Transport` (`publish` and `subscribe`).

Client protocol (JSON, identical over SSE and WebSocket): the server sends `hello`, `capabilities`, `change`, `resync`, `error` and `ping`; the client sends `watch`, `unwatch` and `refresh` (WebSocket only). To use another HTTP framework, forward the stream from `Session::open` and write each message with `ServerMessage::to_sse` or `to_json`.

## JavaScript: Node, Bun and the browser

The package lives in `crates/themis-node/js`. `scripts/build.sh` builds the native module (`js/native/themis.<platform>-<arch>.node`) and the WebAssembly (`js/wasm/`).

```js
import { load } from '@the-hades-organization/themis';
const { Engine, Context } = await load(); // native on Node/Bun, wasm in the browser

const engine = new Engine(spec); // the same EngineSpec as the server
const ctx = new Context({ grants });
engine.check(ctx, { subject, permission: 'document.view', resource });
engine.apply({ actor, current, mutation: { add: grant }, invariants, audit: { level: 'standard' } });
```

On Node and Bun, `load()` tries the native module and falls back to wasm. `THEMIS_BACKEND=native|wasm` forces one of them.

**Frontend.** `PermissionClient` (`/client`) connects over SSE or WebSocket, keeps the capabilities of each scope and decides locally with the same engine. Client-side decisions are for the interface; the server still decides on every operation.

```js
import { PermissionClient } from '@the-hades-organization/themis/client';
const client = new PermissionClient({ url: '/permissions/events', scopes, themis, engine }).connect();
client.on('capabilities', () => render());
client.can('document.edit', resource);
```

**JS backend** (`/server`). `Hub`, `openSession`, `sseResponse` (Fetch API: Bun.serve, Hono, Deno), `pipeSse` (Node's `http`) and the `redisTransport` (node-redis and Bun's `RedisClient`), `ioredisTransport` and `pgTransport` (`pg` package) transports. Notices share the `themis-sync` format, so Rust and JS instances exchange changes over the same channel.

Binding limits: custom condition functions (`call`) and custom overrides exist only in Rust. The JSON spec covers the built-in overrides (`resource_owner`, `permission_holder`).

## Inspector (`themis-inspect`)

An optional crate, outside the `default-members`: `cargo build -p themis-inspect`. The window uses gpui (`gpui-pre =0.3.11` and `gpui-component =0.9.0`); without the `gui` feature (`--no-default-features`) you keep the library and the terminal commands.

```sh
themis-inspect --scenario scenario.json --audit trail.jsonl     # window
themis-inspect --scenario scenario.json --subject beto --permission document.export --resource fatura-7 \
               --disable pro-export --tab matriz                 # window opened on a selection and tab
themis-inspect explain --scenario scenario.json --subject beto --permission document.view --resource secret
themis-inspect matrix  --scenario scenario.json --resource secret --disable no-secret --add grant.json
themis-inspect audit   --audit trail.jsonl --scenario scenario.json
```

The scenario is a JSON file with the policy (`spec`, the same `EngineSpec`), the data (`grants`, `tuples`, `env`) and the subjects and resources to examine, by name. There is an example in `crates/themis-inspect/examples/scenario.json`, with a forensic trail of six decisions in `examples/audit.jsonl`, generated by:

```sh
cargo run -p themis-inspect --no-default-features --example trail -- \
    crates/themis-inspect/examples/scenario.json > crates/themis-inspect/examples/audit.jsonl
```

- **Evaluation** (`avaliacao`): pick a subject, permission and resource and see the decision, the reason, the resource path with the deciding step, the effective roles, each override and the fate of each grant (candidate, unrelated permission, out of scope, target off the path, subject does not match, condition false or not evaluable), with the condition tree and the resolved values. It is built on `Engine::explain`, also available from Rust and JS.
- **Simulation**: turn grants on and off (or add some with `--add`) and see whether the set would allow the access. When the decision changes, the panel also shows the decision with the original grants.
- **Matrix** (`matriz`): every catalog permission for every subject on a resource, with the cells the simulation changed marked. Clicking a cell opens its trace.
- **Audit** (`auditoria`): reads the JSON Lines trail, checks the hash chain of the `forensic` records, shows the recorded trace and re-evaluates `detailed` or `forensic` decisions against the current policy, pointing out the ones that would change.

Files are reloaded on their own when they change on disk. The window embeds the Noto Sans and JetBrains Mono fonts (OFL license, in `crates/themis-inspect/assets/fonts`) and its own icons, so it looks the same on any machine. The interface text is in Brazilian Portuguese.

## Extension points

| Trait | For |
|---|---|
| `GrantSource` | Reading grants from a database, a cache or more than one source (`(A, B)` tuples chain). |
| `TupleStore` | Keeping ReBAC tuples outside memory. |
| `Override` | Owner, superadmin, suspended account, maintenance window. `FnOverride` takes a closure. |
| `Strategy` | Another combination rule. |
| `Invariant` | Another grant change rule. |
| `CatalogRule` | Your own catalog validation (`RequireMeta`, `FnRule`). |
| `AuditSink` | Where the audit trail goes. |
| `Transport` | The medium between instances for change notices. |
| `CapabilityProvider`, `GrantLoader` | How a session computes the capabilities it sends. |
| `ChangeSink` | A synchronous reaction to each change (cache, metric). |

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p themis-node --features napi -- -D warnings
cargo clippy -p themis-node --features wasm --target wasm32-unknown-unknown -- -D warnings
cargo fmt --all --check

# transports against real servers (skipped without the variables)
THEMIS_REDIS_URL=redis://127.0.0.1:6379/ THEMIS_PG_URL=postgres://postgres:pw@127.0.0.1/postgres cargo test --workspace

# JS: build and tests on Node and Bun
crates/themis-node/scripts/build.sh
cd crates/themis-node/js && npm install && node test/run.mjs && bun test/run.mjs
```

The JS tests also accept `THEMIS_RUST_SERVER` (the URL of the `themis-axum` `server` example) to test the client against the Rust server.

The gpui window of `themis-inspect` needs the Wayland and X11 development libraries on Linux (for example `libxkbcommon-dev`, `libwayland-dev`, `libxcb1-dev`, `libvulkan-dev`).

Source comments and the inspector interface are in Brazilian Portuguese; issues and pull requests are welcome in English or Portuguese. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). The fonts embedded in `themis-inspect` are under the SIL Open Font License 1.1 (see `crates/themis-inspect/assets/fonts`).
