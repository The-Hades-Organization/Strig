<p align="center">
  <img src="assets/banner.svg" alt="Strig: who can do what, and why. RBAC, ABAC and ReBAC, one decision engine for Rust." width="100%">
</p>

# Strig

[![CI](https://github.com/The-Hades-Organization/Strig/actions/workflows/ci.yml/badge.svg)](https://github.com/The-Hades-Organization/Strig/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)
[![crates.io](https://img.shields.io/crates/v/strig.svg)](https://crates.io/crates/strig)
[![docs.rs](https://img.shields.io/docsrs/strig)](https://docs.rs/strig)
[![npm](https://img.shields.io/npm/v/@the-hades-organization/strig.svg)](https://www.npmjs.com/package/@the-hades-organization/strig)

**English** · [Português (Brasil)](README.pt-BR.md)

Strig is an authorization library for Rust. You declare a permission catalog, hand the engine your grants, and ask whether a subject may do something to a resource. RBAC, ABAC and ReBAC are evaluated over the same grants. Changes to grants go through governance rules, are audited, and can be pushed in real time to other instances and to the browser.

The core does no IO, needs no async runtime and compiles to WebAssembly. Real time, transports and the JavaScript bindings are separate, optional crates.

[Documentation](https://strig.vercel.app/docs) · [Playground](https://strig-playground.vercel.app) · [API on docs.rs](https://docs.rs/strig) · [Changelog](CHANGELOG.md)

> [!NOTE]
> Strig is pre-1.0: the API can change between minor versions. Versions up to 0.5.0 were published as Themis. The [versioning and deprecation policy](docs/versioning.md) says what counts as public API and what breaks it, [migration.md](docs/migration.md) shows what to change when you upgrade, and [benchmarks](docs/benchmarks.md) has the numbers.

## Install

```sh
cargo add strig                             # Rust
cargo add strig --features dsl              # Rust, with the policy language
npm install @the-hades-organization/strig   # Node, Bun and the browser
```

Features of the `strig` crate:

| Feature | Default | Adds |
|---|---|---|
| `audit` | yes | Audit trail for grant changes and decisions, with a hash chain |
| `exclusive` | no | One holder per resource, with priority and preemption |
| `dsl` | no | The policy language: parse, validate, convert, format. No IO, works in wasm |
| `dsl-fs` | no | `dsl` plus reading and writing `.strig` files and directories |

## Quick start

```rust
use strig::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let engine = Engine::builder(catalog).build()?;

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

    let ctx = Context::new(&grants);
    let export_invoice = engine.decide(&ctx, &Request::new(&dave, "document.invoice.export", &invoice));
    let export = engine.decide(&ctx, &Request::new(&dave, "document.export", &invoice));
    println!("{:?} {:?}", export_invoice.effect, export_invoice.reason);
    println!("{:?} {:?}", export.effect, export.reason);
    Ok(())
}
```

```text
Deny Grant { grant_id: "g2", permission: "document.invoice.export", rank: 1, strategy: "most_specific" }
Allow Grant { grant_id: "g1", permission: "document.export", rank: 3, strategy: "most_specific" }
```

Dave may export documents anywhere in `acme` (`g1`), but not invoices: `g2` sits on `doc_type:invoice`, one step from the document (`rank: 1`), while `g1` sits on `org:acme`, three steps away (`rank: 3`). The rank counts steps from the resource itself (rank 0), and the default strategy lets the lowest rank decide.

The same engine runs in Node, Bun and the browser; see [JavaScript](#javascript-node-bun-and-the-browser).

The same engine can be configured from JSON, TOML or YAML through `EngineSpec`, or from a `.strig` file in the [policy language](#policy-language). `EngineSpec::builder()` returns the `EngineBuilder`, so you can add in code what does not serialize, such as condition functions.

More to run:

```sh
cargo run -p strig --example documents        # RBAC, ABAC and ReBAC in one domain
cargo run -p strig-axum --example server      # real-time server over SSE and WebSocket
```

## Crates

All crates except `strig-inspect` and `strig-node` are on crates.io at the same version.

| Crate | Use it for | Main dependencies |
|---|---|---|
| `strig` | Catalog, decision engine, governance, auditing, JSON spec, policy language | `serde`, `thiserror`; `sha2` with `audit` |
| `strig-sync` | Change hub, `Transport` trait, SSE/WebSocket sessions independent of any web framework, capability cache | `tokio` |
| `strig-redis` | `Transport` over Redis pub/sub | `redis` |
| `strig-postgres` | `Transport` over Postgres `LISTEN/NOTIFY`, sent inside your transaction; grants, tuples, roles and pending requests stored in Postgres | `tokio-postgres` |
| `strig-axum` | axum SSE and WebSocket routes over `strig-sync` sessions | `axum` |
| `strig-server` | HTTP decision server, and a Rust client that denies when it gets no answer | `axum`, `hyper-util` (client) |
| `strig-macros` | `policy!` and `include_policy!`: the policy is validated at compile time | `strig` |
| `strig-node` | The npm package: native module (N-API) for Node and Bun, WebAssembly for the browser | `napi` or `wasm-bindgen` |
| `strig-inspect` | Inspector: decision traces, grant simulation, access matrix, audit trail. Desktop window and terminal commands | `gpui-pre`, `gpui-component` |

```toml
[dependencies]
strig = "0.6"
strig-sync = "0.6"
```

## Concepts

| Concept | Type | What it holds |
|---|---|---|
| Catalog | `Catalog`, `PermissionDef` | Dotted permission keys (`document.invoice.export`), the targets each accepts, `implied_by`, free-form `meta`. Exports and imports JSON. |
| Resource | `Resource`, `Anchor` | A path of steps (anchors) from the most specific to the broadest (`document:7 → doc_type:invoice → project:42 → org:9`), with an implicit `global` at the end, plus attributes. |
| Subject | `Subject` | Id, roles (optionally scoped), principals (`authenticated`, `anonymous` or your own), attributes. |
| Grant | `Grant` | Who (`User`, `Role`, `Principal`, `Relation`, `Any`), which permission, on which target (a kind or an exact step), allow or deny, with an optional scope (an anchor the resource path must pass through) and condition. |
| Engine | `Engine` | Decides. Returns a `Decision` with the effect, the reason, the matched grants and warnings. |
| Governance | `Governance`, `Invariant` | Applies a grant change only if every invariant passes, and audits the outcome. |

The catalog is validated when it is built. It refuses a malformed key, a duplicate, an unregistered target, a missing parent, a cycle, and anything your own `CatalogRule` rejects.

## How a decision is made

1. **Unknown permission.** Deny with `Reason::UnknownPermission`.
2. **Overrides.** They run in order, and the first one that answers decides. `override_except` takes permissions, and the ones they imply, out of an override's reach.
3. **Collection.** A grant is a candidate when all of these hold:
   - its permission is the requested one, or one that implies it;
   - its scope is on the resource path;
   - its target matches a step of the path;
   - its subject matches;
   - its condition is true.
4. **Strategy.** The strategy picks the deciding grant. With no candidate, deny.

A condition or relation that cannot be evaluated (missing attribute, engine without a `TupleStore`) never opens access: the `allow` is dropped, the `deny` still applies, and the reason goes into `Decision::warnings`.

| Strategy | Rule |
|---|---|
| `MostSpecific` (default) | The most specific step with any grant decides; on that step, `deny` wins. |
| `DenyOverrides` | Any `deny` wins. |
| `PermitOverrides` | Any `allow` wins. |
| `FirstApplicable` | The first grant in source order decides. |

## The three models

### RBAC

`RoleGraph::builder().inherit("maintainer", "member")` gives `maintainer` the grants of `member`. `Subject::with_role_in(role, anchor)` limits a role to the resources under that step.

### ABAC

`Grant::when(condition)` attaches a serializable `Condition`. Operands read `subject.*`, `resource.*` and `env.*`.

| Operators | On |
|---|---|
| `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `is_in`, `exists` | Any value |
| `starts_with`, `ends_with`, `contains` | Text (`contains` also tests list membership) |
| `any_in`, `all_in` | Lists |
| `ip_in` | An address in a CIDR or a list of CIDRs |
| `time_between`, `weekday_in` | The decision instant, in UTC or in the IANA zone `tz` |
| `all`, `any`, `not` | Other conditions |
| `call` | Your own function, registered with `ConditionRegistry::register` |

The time conditions read the instant given by `Context::at`; without it they cannot be resolved, so the `allow` does not apply. There is no regular-expression condition. `Engine::validate_grant` checks that every `call` names a registered function.

#### Time zones

Office hours are local, so `time_between` and `weekday_in` take an optional IANA zone: `Condition::time_between("09:00", "18:00").in_tz("America/Sao_Paulo")` in Rust, `{"op": "time_between", "from": "09:00", "until": "18:00", "tz": "America/Sao_Paulo"}` in JSON or JavaScript, and `time_between "09:00" "18:00" tz "America/Sao_Paulo"` or `weekday_in ["mon", "tue"] tz "Europe/Lisbon"` in the policy language. Without `tz` the clock is UTC, as before.

- **Daylight saving time.** The instant decides the local time. A window inside the hour that a spring-forward jump skips never holds that day; the hour that a fall-back repeats holds on both passes. A window that crosses midnight (`"22:00"` to `"06:00"`) and the weekday follow the local date.
- **Unknown names.** The validator refuses a zone it does not know when the policy loads, with position and hint. A condition built without validation fails when evaluated, and an `allow` with an error never applies.
- **Trace.** `explain` shows the local time it used, for example `12:30 America/Sao_Paulo (UTC-03:00)`.
- **Cost.** The zone database is the default feature `tz` of the `strig` crate (`chrono-tz`) and adds about 0.9 MB (0.13 MB gzipped) to the `.wasm`. Without the feature a `tz` is refused at load.

### ReBAC

Store `object#relation@subject` tuples in a `TupleStore` and describe each type in a `RelationSchema` with `This`, `Computed`, `TupleToUserset`, `Union`, `Intersection` and `Exclusion`. `user:*` stands for every user.

A grant with `SubjectMatcher::relation("editor")` applies to whoever holds `editor` on the step its target matched. The search stops at `max_relation_depth` (32 by default) and cuts cycles.

## Governance

`Governance` runs a grant change through a list of invariants and returns the new grant set only if all of them pass. Persist the result on `Ok`; on `Err` you get the violations.

From here on, snippets reuse the `engine`, `grants` and subjects of earlier examples; names such as `actor`, `current` (the grants you hold today) and `request_meta` stand for your own values. The `None` argument is an optional `TupleStore` for ReBAC, and `apply_with` is `apply` plus request metadata for the audit trail.

```rust
let governance = Governance::new()
    .with(CatalogConformance)
    .with(RequirePermission::new("org.roles.edit", org_resource.clone()))
    .with(NoSelfManagement)
    .with(NoLockout::new(["org.invite"], members, org_resource))
    .with(Forbid::new(SubjectMatcher::principal(AUTHENTICATED), ["project.delete"]))
    .audited(auditor);

let next = governance.apply_with(&engine, &actor, &current, &Mutation::Add(grant), None, &request_meta)?;
// persist `next`
```

Assigning or revoking a role goes through the same invariants and is audited as `role_assign` or `role_revoke`. The grant set comes back unchanged; the subject to persist comes from `Mutation::subject_after`.

```rust
let change = Mutation::AssignRole { subject: bob, role: RoleAssignment::in_scope("editor", org) };
governance.apply_with(&engine, &actor, &current, &change, None, &request_meta)?;
let bob = change.subject_after().expect("role change"); // persist bob's roles
```

`Forbid` applies to a role assignment only when the assignment targets a user, and it ignores scope. Write your own rule by implementing `Invariant`. The invariant list can also come from JSON (`InvariantSpec`).

### Approving a change before it applies

A change the policy marks as needing approval does not apply on the spot: it waits as a pending request that another actor approves or refuses. The policy is per kind of change and names who approves.

```rust
let policy = ApprovalPolicy::new()
    .require(MutationKind::Add, "org.approve", org_resource.clone())
    .require(MutationKind::AssignRole, "org.approve", org_resource);
let store = MemoryPendingStore::new();
let flow = Approvals::new(&governance, &policy, &store);
let review = Review { engine: &engine, current: &current, tuples: None, now, meta: &request_meta };

// Ana proposes; the invariants judge it and, if they accept, it is kept (expires in an hour).
let Proposed::Pending(request) = flow.propose(&review, &ana, &Mutation::Add(grant), "req-1", Some(now + 3_600_000))? else {
    unreachable!("the policy covers Add");
};

// Caio approves: he needs `org.approve`, he is not Ana, and the invariants run again over `current`.
let approved = flow.approve(&review, &caio, &request.id)?;
// persist `approved.grants`
```

An approver who is the author, lacks the permission, or meets invariants that now refuse gets `ApprovalError::Refused` and the request stays pending; `reject(&review, &caio, id, "reason")` closes it with a reason, and `expire_due(now, &meta)` closes the ones whose expiry came (approving a due request closes it too). With an auditor on the governance, every step is a record (`mutation_propose`, `mutation_approve`, `mutation_reject`, `mutation_expire`; see [`docs/audit-format.md`](docs/audit-format.md)), and the approval record is written before the change is applied. The crate keeps no clock and no database: pass the instant, and serialise approvals of one request when several processes share a store. Not covered: several approvers (quorum) and the author withdrawing their own request.

In JavaScript the engine judges and audits each step and `Approvals` keeps the requests:

```js
import { Approvals, MemoryPendingStore } from '@the-hades-organization/strig/approvals';

const flow = new Approvals(engine, new MemoryPendingStore(), {
  approval: [{ kind: 'add', permission: 'org.approve', resource: orgResource }],
  invariants,
});
const proposed = await flow.propose(ana, { add: grant }, grants, { id: 'req-1', expiresAt: Date.now() + 3_600_000 });
const done = await flow.approve('req-1', caio, grants, { persist: (r) => saveGrants(r.grants) }); // `persist` runs before the request is marked approved
await flow.reject('req-2', caio, 'outside the change window', grants);
await flow.expire();
```

`JsonFileStore` keeps the requests in the same file (`new Approvals(engine, store.pendingStore, options)`, and `store.approvePending(flow, id, approver)` persists the grants before marking the request approved). Without a rule for its kind, `propose` applies the change at once (`applied: true`).

### Rules declared in the catalog

Some rules belong to a permission, so they are declared on its `PermissionDef`:

| Flag | Effect |
|---|---|
| `depends_on` | Holding the permission requires holding each listed one on the same resource (checked by `Prerequisites`). |
| `non_delegable` | Only a manager hands it out, not whoever merely holds it. |
| `management_only` | Grantable only to management roles. |
| `override_only` | Valid only through an override; a plain grant of it does not count. |

`NoEscalation` keeps an actor from handing out what they do not hold: an `allow` grant or a role assignment is refused unless the actor holds every permission it confers, and every permission those imply, wherever it would apply. Holding `org.roles.edit` is therefore not a way to give someone a stronger role than your own.

```rust
let catalog = Catalog::builder()
    .target_kind("project")
    .permission(PermissionDef::new("project.view").targets(["project"]))
    .permission(PermissionDef::new("project.edit").targets(["project"]).depends_on(["project.view"]))
    .permission(PermissionDef::new("project.share").targets(["project"]).non_delegable())
    .permission(PermissionDef::new("project.purge").targets(["project"]).override_only())
    .build()?;
let engine = Engine::builder(catalog).build()?;

let governance = Governance::new()
    .with(CatalogConformance)
    .with(Prerequisites)
    .with(NoEscalation::new());

// `lead` holds `project.edit` only, so handing out `project.view` is an escalation.
let current = vec![Grant::allow("l", SubjectMatcher::user("lead"), "project.edit", TargetSelector::kind("project"))];
let handout = Mutation::Add(Grant::allow("a", SubjectMatcher::user("ana"), "project.view", TargetSelector::kind("project")));
let refused = governance.apply(&engine, &Subject::user("lead"), &current, &handout, None).unwrap_err();
assert_eq!(refused[0].invariant, "no_escalation");
```

Two more tools:

- **Lockout reserve.** `NoLockout::with_reserve` names who should take over a critical permission. When a change would leave that permission with no holder, the `Violation` carries a `Suggestion` with the role assignment that fixes it. Nothing is applied; the suggestion is also written to the audit record.
- **Role templates.** `RoleTemplate::materialize` turns a template into ordinary grants. The template id and version go into the change metadata; the grants keep no link to the template.

## Auditing

With the `audit` feature, every change that goes through governance becomes an `AuditRecord`, applied or refused. Record ReBAC tuples and role assignments with `Auditor::tuple_change` and `Auditor::role_change`. If the sink fails to write, governance refuses the change with the `audit` violation: no record, no change (unless you choose `FailMode::Open`, below).

```rust
let auditor = Arc::new(Auditor::new(AuditLevel::Standard, Arc::new(JsonLinesAudit::new(file))));
```

Built-in sinks are `MemoryAuditLog` and `JsonLinesAudit`, which writes to any `io::Write`. To send records to a database, a queue or a SIEM, implement `AuditSink`.

### What each level keeps

Each level keeps everything from the one above it. Sizes are compact JSON bytes per line of JSON Lines, without compression or indexes, measured on a reference record (`audit::reference_record`): a grant with a scope and a two-clause condition, UUID ids, an actor with two roles and three request metadata entries.

| Level | Change records keep | Bytes | Per 1M records |
|---|---|---:|---:|
| `minimal` | When, who, action, object id, outcome | 175 | 175 MB |
| `standard` | + grant summary (permission, subject, target, effect, scope, has a condition) and the names of the invariants that refused | 388 | 388 MB |
| `detailed` | + the whole grant with its condition, the full actor, the violation messages, the request metadata | 1,097 | 1.10 GB |
| `forensic` | + SHA-256 digest of the grant set before and after, and the hash chain | 1,415 | 1.42 GB |

Decisions can be audited too: `Auditor::decide(&engine, &ctx, &request, &meta)` decides and records. The reference decision (`audit::reference_decision_record`) has three grants in the source, one with a condition, a resource with three steps, UUID ids and three metadata entries.

| Level | Decision records keep | Bytes | Per 1M records |
|---|---|---:|---:|
| `minimal` | When, subject, `permission@resource`, allowed or denied | 285 | 285 MB |
| `standard` | + the reason (override, deciding grant and step, or no grant) and the matched grants | 669 | 669 MB |
| `detailed` | + the full subject and resource, the warnings, the request metadata. Enough to re-evaluate the decision later | 1,239 | 1.24 GB |
| `forensic` | + the full trace from `Engine::explain`, and the hash chain | 3,582 | 3.58 GB |

To project your own volume, call `AuditLevel::estimate_bytes(n)` for changes and `AuditLevel::estimate_decision_bytes(n)` for decisions; the forensic decision size grows with the number of grants the source returns. In a database, add the row overhead (about 28 bytes per row in Postgres) and your indexes.

The numbers are checked: the `estimates_match_reference_records` and `decision_estimates_match_reference_records` tests fail if a measured size drifts more than 10% from the table, and `cargo run -p strig --example audit_storage` measures again.

### Hash chain

At the `forensic` level each record carries the hash of the previous one. `audit::verify_chain` detects an edited or removed record, and `Auditor::resume_chain` continues the chain after a restart.

The exact bytes of a record and the hash computation, with a test vector another language can reproduce, are in [docs/audit-format.md](docs/audit-format.md). The same page explains how to take only the records and chain them in your own log, and how to anchor the head of the chain outside (`Auditor::chain_head`, then `verify_chain_anchored(&records, start, head)`), which is what catches records cut off the end.

### When the sink fails

By default a sink that fails refuses the change (`FailMode::Closed`). With `FailMode::Open` the change goes ahead and the record waits in an in-memory retry queue, in order, with a capacity and a backoff you set (`RetryPolicy`); `AuditStatus::Pending` says it is waiting and `Auditor::stats()` counts what is waiting or was dropped. The mode is chosen per call (`governance.at(now).fail_mode(..)`, `Auditor::grant_mutation_with`), per permission (`with_permission_fail_mode`) or as the auditor's default (`with_fail_mode`), in that order of precedence.

```rust
let auditor = Auditor::new(AuditLevel::Forensic, sink)
    .with_fail_mode(FailMode::Closed)
    .with_permission_fail_mode("report.view", FailMode::Open)
    .with_retry(RetryPolicy { capacity: 500, ..RetryPolicy::default() })
    .with_redactor(mask_attributes(["ip", "email"], "[redacted]"));
```

`with_redactor` masks attributes before the record is hashed and written, so the hash covers the masked version.

In JS the sink is a synchronous function; a throw is a failure of the sink:

```js
const engine = new Engine(spec, {
  auditSink: (record) => log.append(record),
  auditPolicy: { failMode: 'closed', permissions: { 'report.view': 'open' }, capacity: 500 },
  onAuditDrop: (record) => spill.write(record),
});
const out = engine.apply({ actor, current, mutation, audit: { level: 'forensic', prevHash, failMode: 'open' } });
out.auditStatus;                 // 'written' | 'pending' | 'dropped'
engine.flushAudit();             // retries the queue, answers { pending, writtenLate, dropped, failures, nextRetryAt }
verifyAuditChain(records, { start, head }); // { ok: true, head } or { ok: false, code }
```

## Validity windows

`Grant::valid_between(from, until)` limits a grant in time; `valid_from` and `valid_until` set one end.

- Times are milliseconds since the Unix epoch. The window includes `from` and excludes `until`.
- The caller supplies the instant: `Context::at(now)` for decisions, `Governance::at(now)` for changes.
- Without an instant, a grant with a window does not apply, so a missing clock denies.

```rust
let grant = Grant::allow("w", SubjectMatcher::user("ana"), "project.view", TargetSelector::kind("project"))
    .valid_between(1_000, 2_000);
let grants = vec![grant];
let ana = Subject::user("ana");
let project = Resource::new("project", "p1");
let request = Request::new(&ana, "project.view", &project);

assert!(engine.check(&Context::new(&grants).at(1_500), &request));
assert!(!engine.check(&Context::new(&grants).at(2_000), &request));
assert!(!engine.check(&Context::new(&grants), &request));
```

`CapabilityCache` expires its entries at the next window boundary. Removing expired grants from storage is left to a job of yours.

## Reverse queries and filtered listing

Ask who can do something, or what a subject can reach, instead of checking one request. `QueryContext` carries the grants (and `.at(now)`), `QueryLimits` bounds the work, and `PgTables` turns the answers into SQL.

```rust
let qctx = QueryContext::new(&grants).at(1_500);
let filter = engine.list(&qctx, &ana, "project.view", "project");
let who = engine.who_can(&qctx, "project.view");
assert_eq!(who, vec![SubjectRef::User { id: "ana".into() }]);
```

| Call | Returns |
|---|---|
| `engine.list(&qctx, &subject, permission, kind)` | An `AccessFilter` over the resources of that kind the subject can reach, ready to become a `WHERE` clause. |
| `engine.who_can(&qctx, permission)` | Everyone named by an allow grant of the permission, anywhere. Denies, overrides and conditions are not evaluated. |
| `engine.who_can_on(..)` | The same on one resource, with denies, overrides and conditions evaluated. |
| `engine.access_of(..)` | Everyone with access to a resource, and their permissions. |
| `engine.check_for(..)` | A check by subject reference: a `SubjectResolver` loads the subject, and the answer names the path that decided. |

## Exclusive resources

With the `exclusive` feature, a resource can have one holder at a time. `Terms::new(priority, ttl_ms)` sets how strong the claim is and how long it lasts. A higher priority takes the resource over only when the claimant also holds `exclusive.preempt`. Permissions and time are checked by the same engine as any other decision.

```rust
let mut registry = ExclusiveRegistry::default();
let now = 0; // milliseconds since the Unix epoch, passed by the caller
let first = registry.acquire_checked(&engine, &ctx, &ana, &document, Terms::new(1, 60_000), now)?;
assert_eq!(first, Acquisition::Granted);

let second = registry.acquire_checked(&engine, &ctx, &bob, &document, Terms::new(9, 60_000), now + 10)?;
assert!(matches!(second, Acquisition::Preempted { .. }));
```

## Real time

```text
grant change ──► Hub::publish ──► local sessions (SSE/WebSocket) and CapabilityCache
                      │
                      └─► Transport (Redis, Postgres, your own) ──► Hub on the other instances
```

```rust
let hub = Hub::builder()
    .transport(RedisTransport::new("redis://127.0.0.1/", "strig:changes")?)
    .build();
let _relay = hub.spawn_relay();

let cache = Arc::new(CapabilityCache::new(Duration::from_secs(30), 10_000));
hub.on_change(cache.clone());
let provider = EngineProvider::new(engine, my_grant_loader).with_cache(cache);
let realtime = strig_axum::Realtime::new(hub).with_provider(Arc::new(provider));
// in the routes: realtime.sse(subject, scopes) or realtime.websocket(upgrade, subject, scopes)
```

A change notice (`Change`) says what kind of change happened and on which step, without the grants. Receivers reload from their own source, so any transport can carry it.

A session watches scopes, that is, anchors such as `org:acme`. With a `CapabilityProvider`, it sends its client the capabilities (the permissions the subject holds) of each affected scope, and changes that arrive together are recomputed once. When the transport drops and comes back, or a client falls behind, the hub emits `Resync` and everything is reloaded.

| Transport | Crate | Notes |
|---|---|---|
| Redis | `strig-redis` | Pub/sub; publishing reconnects on its own. |
| Postgres | `strig-postgres` | `LISTEN/NOTIFY`. Call `strig_postgres::notify(&tx, channel, &change)` inside the transaction that writes the grant, and the notice goes out only on commit. TLS through `PgTransport::with_tls`. |
| Your own | | NATS, Kafka or any broker: implement `Transport` (`publish` and `subscribe`). |

The client protocol is JSON and identical over SSE and WebSocket. The server sends `hello`, `capabilities`, `change`, `resync`, `error` and `ping`; the client sends `watch`, `unwatch` and `refresh` (WebSocket only). For a web framework other than axum, forward the stream from `Session::open` and write each message with `ServerMessage::to_sse` or `to_json`.

## Postgres storage

`strig-postgres` also keeps the data in Postgres: grants, ReBAC tuples, role assignments and pending requests, behind the same traits the engine already reads (`GrantSource`, `GrantIndex`, `TupleStore`, `TupleIndex`, `PendingStore`).

```rust
use strig_postgres::{PgPendingStore, PgStore, PgTables, connect, migrate_with};

let tables = PgTables::default().in_schema("authz")?.with_prefix("strig")?; // schema and names are yours
let client = connect(&url).await?;
migrate_with(&client, &tables).await?; // idempotent, versioned, safe on every boot

let store = PgStore::load(&client, tables.clone()).await?;
let grants = store.grants(); // GrantSource + GrantIndex, served from memory
let tuples = store.tuples(); // TupleStore + TupleIndex
let _follower = store.follow(hub.subscribe(), move || connect(&url), Duration::from_secs(1));
```

- **Why a snapshot.** The core does no IO and `GrantSource` is synchronous, so `PgStore::load` reads the tables and the engine is served from memory. The snapshot reloads when the transport delivers a `Change` (grants, tuples or resync; a lagging receiver reloads everything). A store only exists loaded, so the engine never decides over an empty set that is missing a deny. If a reload fails the previous snapshot stays and `is_stale()` turns true: put it in your readiness probe. The snapshot holds every grant and tuple, so size it for that; for very large tuple sets keep answering `TupleStore` from your own indexed query.
- **Writing.** `put_grant`, `delete_grant`, `put_tuple`, `delete_tuple`, `assign_role` and `revoke_role` take a client or a transaction. `commit_mutation(&tx, channel, &mutation)` writes what a `Mutation` changes and sends its `NOTIFY` in the same transaction, so the notice goes out if, and only if, the change commits. Call `lock_governance(&tx)` first and read `all_grants(&tx)` inside the transaction, so two instances never judge a change against the same stale set.
- **Governance end to end.** Read the grants and the actor (`tables.subject(&tx, "user", id)` builds the `Subject` with its stored roles), run `Governance::apply`, then `commit_mutation` and commit. Other instances reload on the notice.
- **Roles.** `strig_roles` keeps the assignments per subject (role, optional scope, optional window). A subject read from it carries the `authenticated` principal when its kind is `user`.
- **Pending requests.** `PgPendingStore` is a `PendingStore` over a table, with the expiry in an indexed column (`due(now)` lists what `expire_due` closes). The trait is synchronous, so the store owns a connection on its own thread and each call blocks for one round trip: call it from `spawn_blocking` inside async code. A call that does not answer in time (10 s by default) is a `PendingError::Store`, which refuses, and `update` is one `UPDATE ... WHERE state = 'pending'`, so a request decided meanwhile by another process is never decided twice.
- **Migrations.** `migrate`/`migrate_with` embed the SQL, record each version in `<prefix>_migrations` and run in one transaction under an advisory lock. They are additive (`CREATE ... IF NOT EXISTS`); nothing drops or rewrites data. Schema and table names are validated as plain identifiers.

The tests run against a real Postgres when `STRIG_PG_URL` is set (see Development) and skip without it.

## Decision server and remote client

`strig-server` answers decisions over HTTP, for services that do not embed the engine.

```rust
let source = Arc::new(MemorySource::new(Snapshot::new(Arc::new(engine), grants)));
let router = DecisionServer::new(source).router();
let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
axum::serve(listener, router).await?;
```

The router serves `POST /v1/check`, `/v1/check/batch`, `/v1/list`, `/v1/who` and `/v1/access`, plus `GET /health/live` and `/health/ready`. Grants come from a `DecisionSource`; `MemorySource` holds a `Snapshot` you can `replace`. Decisions use the server's clock. The full contract is in [`crates/strig-server/API.md`](crates/strig-server/API.md).

The client fails closed. Only a `200` counts as an answer: a timeout, a refused connection, a `503` or an unreadable body becomes `ClientDecision::Denied` with the reason, and a circuit breaker stops calling a server that keeps failing.

```rust
let config = ClientConfig::default()
    .with_timeout(Duration::from_millis(250))
    .with_breaker(BreakerConfig::default().with_failure_threshold(5).with_open_for(Duration::from_secs(10)));
let client = Client::http("http://127.0.0.1:8080", config);

let request = CheckRequest::new(Subject::user("alice"), "document.view", Resource::new("document", "d1"));
if client.check(&request).await.is_allowed() {
    // serve the document
}
```

## JavaScript: Node, Bun and the browser

```sh
npm install @the-hades-organization/strig
```

```js
import { load } from '@the-hades-organization/strig';
const { Engine, Context } = await load(); // native on Node/Bun, wasm in the browser

const engine = new Engine(spec); // the same EngineSpec JSON as in Rust
const ctx = new Context({ grants });
engine.check(ctx, { subject, permission: 'document.view', resource });
engine.apply({ actor, current, mutation: { add: grant }, invariants, audit: { level: 'standard' } });
```

On Node and Bun, `load()` tries the native module and falls back to wasm. Set `STRIG_BACKEND=native` or `STRIG_BACKEND=wasm` to force one.

The native module ships as one small package per platform, installed by npm as an optional dependency of `@the-hades-organization/strig` (a typical install is about 2 MB to download and 8 MB on disk):

| Platform | Package |
| --- | --- |
| Linux x64 and arm64 (glibc) | `strig-linux-x64-gnu`, `strig-linux-arm64-gnu` |
| macOS Intel and Apple silicon | `strig-darwin-x64`, `strig-darwin-arm64` |
| Windows x64 | `strig-win32-x64-msvc` |

Any other platform (Alpine/musl, for example) runs on the wasm backend, which is bundled in the main package. If you install with `--omit=optional` (or `--no-optional`), `load()` falls back to wasm too, and `STRIG_BACKEND=native` throws an error naming the package to install.

The JSON spec covers the built-in overrides, `resource_owner` and `permission_holder`. Custom condition functions (`call`), custom overrides and custom invariants are not part of the spec: in JS they are synchronous callbacks passed to the `Engine` constructor (see "Rules written in JavaScript").

### In the browser

`PermissionClient` (`/client`) connects over SSE or WebSocket, keeps the capabilities of each scope and decides locally with the same engine. Use it to shape the interface; the server still decides on every operation.

```js
import { PermissionClient } from '@the-hades-organization/strig/client';
const client = new PermissionClient({ url: '/permissions/events', scopes, strig, engine }).connect();
client.on('capabilities', () => render());
client.can('document.edit', resource);
```

### Cost of a call and batches

A `Context` keeps its grants, tuples, `env` and instant on the Rust side, so a decision never sends them again; change them with `addGrant` (the same `id` replaces), `removeGrant`, `addTuple`, `removeTuple`, `setNow` and `setEnv`. What still crosses the boundary on each call is the request, and the binding sends it as one `JSON.stringify` string (the decision comes back the same way) when it is plain JSON; a request with `undefined`, `NaN`, functions, bigints or class instances takes the original path and its errors. `check` answers a boolean without building the `Decision`.

To decide many requests against one `Context` and one instant, cross the boundary once:

```js
const allowed = engine.checkMany(ctx, requests);   // boolean[], in order
const traces = engine.explainMany(ctx, requests);  // Explanation[], in order
```

A request that cannot be read throws and decides none; it never becomes a silent `false`. Numbers per case are in [`docs/benchmarks.md`](docs/benchmarks.md).

### Rules written in JavaScript

The `call` condition function, your own override and your own `Invariant` exist in JS too, as synchronous callbacks passed to the `Engine` constructor. The engine calls them in the middle of a decision or of `apply`; they show up like the native ones: the `explain` trace names the override, a refusal carries your violation, and the audit records it as it records the built-in invariants.

```js
const engine = new Engine(spec, {
  // `call` conditions: { op: 'call', func: 'same_dept', args: [{ attr: 'subject.dept' }, { attr: 'resource.dept' }] }
  conditions: { same_dept: ([a, b]) => a === b },
  // Decides before the grants: 'allowed', 'denied' or 'abstained' (nothing). `except` skips permissions.
  overrides: [{ name: 'frozen', except: ['project.view'], evaluate: ({ permission }) => (frozen ? 'denied' : undefined) }],
  invariants: {
    // The role of an environment never exceeds the global one.
    env_role_within_global({ mutation }) {
      if (!('assign_role' in mutation)) return;
      const { subject, role } = mutation.assign_role;
      if (role.scope?.kind !== 'environment' || rank(role.role) <= globalRank(subject)) return;
      return { message: `${role.role} in the environment exceeds the global role`, suggestion: downgrade(subject, role) };
    },
    // A role in use is not deleted.
    role_in_use({ mutation, before }) {
      if (!('remove' in mutation)) return;
      const grant = before.find((g) => g.id === mutation.remove.id);
      if (grant?.subject.kind === 'role' && inUse(grant.subject.id)) return `role ${grant.subject.id} is in use`;
    },
  },
});

engine.apply({ actor, current, mutation, invariants: [{ kind: 'custom', name: 'env_role_within_global' }, { kind: 'custom', name: 'role_in_use' }] });
```

- A condition function gets the resolved operands and returns a boolean. An invariant gets `{ actor, mutation, before, after, now }` (the `mutation` has the shape `apply` takes) and returns nothing to accept, or a text, or `{ message, suggestion? }` to refuse. The `suggestion` is a change; the governance re-checks it against every invariant before it surfaces.
- **A throw denies, never crashes.** A condition that throws (or does not return a boolean) is a condition error: an allow grant does not apply, a deny grant still does, and the trace carries the message. An override that throws answers `denied`. An invariant that throws refuses with the message of the error.
- **Callbacks are synchronous.** A promise is not awaited; it is a wrong answer and denies like a throw.
- **No re-entry.** A callback that calls the engine, or changes another `Context`, gets `REENTRANT_CALL`; changing the `Context` under decision is refused by the runtime. Read what you need before the call and keep it in the closure.
- A custom override is opaque to listings (`list`), like any override that does not describe its reach: the resources it might decide on stay as residue, never as allowed.

### Real time on a JS backend

`/server` has `Hub`, `openSession`, `sseResponse` (Fetch API: Bun.serve, Hono, Deno), `pipeSse` (Node's `http`) and three transports: `redisTransport` (node-redis and Bun's `RedisClient`), `ioredisTransport` and `pgTransport` (the `pg` package). Notices use the `strig-sync` format, so Rust and JS instances can share a channel.

### Grants and roles in a JSON file

For a system with neither Postgres nor Redis, `/store` keeps the grants and the role assignments in one JSON file (Node and Bun):

```ts
import { openJsonStore } from '@the-hades-organization/strig/store';

const store = await openJsonStore({ path: './strig.json', createIfMissing: true });
const provider = engineProvider({ engine, Context, loadGrants: store.loadGrants }); // the grant source
const subject = store.subject({ kind: 'user', id: 'ana' });                          // + the roles in the file

const result = await store.apply(engine, { actor, mutation: { assign_role: { subject, role: { role: 'admin' } } }, invariants });
// accepted: the new grants and roles are written; refused: nothing is written
```

- **File:** `{ "version": 1, "grants": [...], "roles": { "<subject id>": [<assignment>, ...] } }`. Roles themselves (the hierarchy) stay in the engine spec; the file holds who has which.
- **Fails closed.** A missing file, invalid JSON, a repeated grant id or a `version` other than 1 throws `JsonStoreError` (`STORE_NOT_FOUND`, `STORE_CORRUPT`, `STORE_VERSION`) on load. The store never starts empty on its own; `createIfMissing` is the explicit way to start one.
- **Writes are atomic and serialised.** Temp file in the same directory, `fsync`, `rename`, then `fsync` of the directory. Calls in one process queue up; between processes a `<file>.lock` (created with `O_EXCL`) is held, and a lock whose owner died on this host, or that is older than `lockStaleMs` (30 s), is taken over. Each change re-reads the file under the lock, so processes do not overwrite each other. `STORE_LOCK_TIMEOUT` after `lockTimeoutMs` (5 s).
- **Changes:** `addGrant`, `updateGrant`, `removeGrant`, `assignRole`, `revokeRole`, `setRoles`, or `apply(engine, input)`, which runs the governance over the grants the file holds right now and persists what it accepts.
- **Reload:** `reload()` after an outside edit, or `watch()` to reload on its own (it watches the directory, since the rename replaces the file). A bad file on reload keeps the last good snapshot, throws from `reload()` and goes to `onError` from `watch()`. `onChange` fires after every reload and write.
- Not here: audit records and a Rust-only store.

### Express, Fastify and NestJS

The three integrations take the same options and decide on each route:

```js
import { load, scopeFromString } from '@the-hades-organization/strig';
import { authorize } from '@the-hades-organization/strig/express';

const { Engine, Context } = await load();
const options = {
  subject: (req) => (req.headers['x-user'] ? { kind: 'user', id: req.headers['x-user'] } : undefined),
  resource: (req) => scopeFromString(`document:${req.params.id}/org:o1`),
  local: { engine: new Engine(spec), context: new Context({ grants }), now: () => Date.now() },
};

app.get('/doc/:id', authorize({ ...options, permission: 'document.view' }), handler);
```

| Option | Meaning |
|---|---|
| `subject(req)` | The subject; returning nothing answers `401`. |
| `resource(req)` | The resource. |
| `local: { engine, context, now }` or `remote: RemoteClient` | Where the decision comes from. Pass exactly one. |

The request never passes unless the decision allows it:

| Outcome | Status | Change it with |
|---|---|---|
| No subject | `401` | `unauthenticatedStatus` |
| Denied | `403` | `denyStatus` |
| The decision could not be made | `503` | `failureStatus` |
| Your `subject` or `resource` function threw | `500`, with no detail | `errorStatus`, `onError` |

- **Fastify** (`/fastify`): the same `authorize`, plus a `plugin` that adds `fastify.strigCan`.
- **NestJS** (`/nestjs`): `@Can('document.view')` on a handler or controller, with `new StrigGuard(options)` as the guard.

#### One route table, deny by default

To keep every rule in one place, give the integration a table instead of a permission per handler. A request no rule covers is refused (`denyStatus`, 403); a route is public only when its rule says `public: true`.

```js
import { authorizeRoutes } from '@the-hades-organization/strig/express';

const routes = [
  { method: 'GET', path: '/health', public: true },
  { method: 'GET', path: '/doc/:id', permission: 'document.view', resource: (req, params) => docScope(params.id) },
  { method: ['PUT', 'DELETE'], path: '/doc/:id', permission: 'document.edit', resource: (req, params) => docScope(params.id) },
];
app.use(authorizeRoutes({ subject, local: { engine, context }, routes })); // before the routers
```

Paths use the framework syntax: literal segments, `:name` for one segment, a trailing `*` for one or more. The first matching rule decides, so write the specific ones first; `HEAD` falls under `GET` rules, and `*` as the method means any. The table matches the way the framework routes, so no request can slip past a protected rule into a broader public one: every segment is percent-decoded before the comparison (`/%61dmin/1` is `/admin/1`; `%2F` stays inside its segment; a malformed escape matches nothing), and literals ignore case with `caseSensitive: false`. The default is the framework's own: Express ignores case, Fastify is case sensitive (set `caseSensitive` on the table if you changed the Fastify option), Nest follows its platform. Pass `{ caseSensitive: false }` to `assertRoutesCovered` for an Express app. Each rule has `permission` or `public: true` (a bad table throws at startup). `resource` receives the request and the matched `params`: at app level Express has not filled `req.params` yet.

- **Express** (`/express`) and **Fastify** (`/fastify`): `authorizeRoutes(options)` is a global middleware or `onRequest` hook (`fastify.addHook('onRequest', ...)`). It also answers 403 for URLs with no route, and a CORS preflight needs a rule or has to be answered before it.
- **NestJS** (`/nestjs`): `{ provide: APP_GUARD, useValue: new StrigRouteGuard(options) }`. The table decides first. If it allows, a `@Can` on the handler adds a second check that must also pass: `@Can` narrows, it never opens what the table denies (and it applies on a `public` rule too). A handler without `@Can` needs nothing else.

Put the table under test so it cannot drift from the app (`/testing`):

```js
import { expressRoutes, assertRoutesCovered } from '@the-hades-organization/strig/testing';

assertRoutesCovered(expressRoutes(app), routes); // throws listing routes with no rule and rules with no route
```

`expressRoutes(app)` reads an Express 4 or 5 app or router (nested routers included, not mounted sub-apps); `nestRoutes(app)` does it for a Nest app on the Express adapter after `app.init()`; on Fastify call `collectFastifyRoutes(fastify)` before registering routes and pass the array it returns once the app is ready. `auditRoutes(routes, table)` returns `{ uncovered, unusedRules, ok }` if you prefer to assert yourself.

Express, Fastify and NestJS are optional peer dependencies. An integration you do not import costs nothing, and importing one whose peer is missing throws `MissingPeerError`.

To get decisions from a [decision server](#decision-server-and-remote-client) instead, pass a `RemoteClient` (`/remote`) as `remote`. It has a timeout and a breaker, and denies when there is no answer:

```js
import { RemoteClient } from '@the-hades-organization/strig/remote';
const remote = new RemoteClient({ url: 'http://127.0.0.1:8080', timeoutMs: 250 });
const { allowed } = await remote.check({ subject, permission: 'document.view', resource });
```

### Catalog types for the frontend

A permission can carry its display name and description per locale (`labels` / `descriptions`, next to `label` / `description`; in Rust `PermissionDef::localized_label("pt-BR", "Editar")`). They are optional and are not declared in the policy language, only in the catalog export (JSON) or the builder. `strig-types` turns an exported catalog into one `.ts` file with the `PermissionId` union, a `PERMISSIONS` constant with the metadata and the helpers `isPermissionId`, `permissionLabel` and `permissionDescription` (locale with fallback to the default text). The output is sorted, so it only changes when the catalog does.

```sh
npx strig-types catalog.json -o src/permissions.generated.ts
```

```ts
import { generateTypes } from '@the-hades-organization/strig/types'; // same thing, as a function
import { PermissionClient } from '@the-hades-organization/strig/client';
import type { PermissionId } from './permissions.generated';

const engine = new strig.Engine<PermissionId>(spec); // strict: check, explain, list, whoCan... take only the ids; without the parameter, any string
const client = new PermissionClient<PermissionId>(/* ... */);
client.can('users:read', resource); // only ids of the union compile; narrow a plain string with isPermissionId first
```

## Policy language

With the `dsl` feature, a policy can be written as text instead of JSON. The same policy has three syntaxes, Blocks, Rules and Actors, and `convert` moves between them. Every error carries a position and a hint. The validated JSON stays the source of truth.

Try it in the [playground](https://strig-playground.vercel.app), which runs the real engine compiled to WebAssembly. The [guide](docs/dsl.md) has the three syntaxes side by side and the grammar.

```rust
use strig::dsl::{self, Language};

const SOURCE: &str = "language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
";

let parsed = dsl::parse("policy.strig", SOURCE)?;
let json = parsed.policy.to_json()?;
let as_rules = dsl::convert(SOURCE, Language::Rules)?;
```

`as_rules` holds:

```text
language rules

kinds org

permission org.read on org
```

Conditions in `when` read the same in the three syntaxes, for example `a starts_with b`, `env.ip ip_in "10.0.0.0/8"`, `time_between "09:00" "17:30"` and `weekday_in ["mon", "tue"]`. The validator refuses a CIDR, a time of day, a weekday or a time zone it cannot read. When a name is one typo away from a declared permission, role or parent, the hint adds ``did you mean `x`?``.

- **Formatting.** `strig::dsl::format` and `is_formatted` rewrite a source in the canonical layout of its syntax and keep the comments. `strig-inspect fmt [--check] <file|dir>` does the same for `.strig` files; `--check` lists the files that would change and exits with 1.
- **Files.** With `dsl-fs`, `strig::dsl::fs::read_dir` reads every `*.strig` file of a directory into a `Project`, and `write_file` writes a policy back.

### In Node

The binding exposes the same language, native and WebAssembly, behind `load()`. A compiled policy is the canonical JSON, the same for the three syntaxes, with the comments in `notes`.

```js
import { load } from '@the-hades-organization/strig';
const strig = await load();

const source = `language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
`;

const policy = strig.compile(source, { file: 'policy.strig' }); // canonical JSON
const rules = strig.print(policy, 'rules'); // 'blocks' | 'rules' | 'actors'
const actors = strig.convert(source, 'actors'); // text to text
const merged = strig.loadProject([
  { path: 'org.strig', text: source },
  { path: 'team.strig', text: strig.convert(source.replaceAll('org', 'team'), 'actors') },
]);
const fromDisk = strig.loadProjectDir?.('./policy'); // native module only
```

- `format(source)` returns the source in the canonical layout of its syntax; `isFormatted(source)` says whether it already is.
- `loadProjectDir(dir)` exists only on the native module, since WebAssembly has no file access. It reads the `*.strig` files of the directory and refuses a policy file that is a symbolic link. Pass only a `dir` from a trusted source.

Every failure is an `Error` whose `code` is the same on both targets:

| `code` | Cause |
|---|---|
| `DSL_PARSE` | The text does not parse. |
| `DSL_VALIDATE` | The policy parses but is invalid. |
| `DSL_CONFLICT` | Two sources declare the same thing; both positions are reported. |
| `DSL_UNREPRESENTABLE` | The target syntax cannot express the policy. |
| `DSL_UNSUPPORTED` | The syntax is not available in this build. |
| `DSL_LIMIT` | A size or count limit was exceeded. |
| `DSL_DUPLICATE_SOURCE` | The same `path` appears twice in `loadProject`. |
| `DSL_IO` | A file or a link in `loadProjectDir`. The message carries the path, so do not forward it to a remote client. |

`error.diagnostics` lists up to 100 `{ file, line, column, message, hint, related? }` entries; when more were found, the last entry says "and N more". `file`, `line` and `column` are `null` for a policy that did not come from text. `related` (`{ file, line, column }`) appears on a `DSL_CONFLICT`.

```js
try {
  strig.compile('language blocks\n\npermission {', { file: 'a.strig' });
} catch (error) {
  error.code; // 'DSL_PARSE'
  const [first] = error.diagnostics; // first.file === 'a.strig', first.line === 3
}
```

### Macros

`policy!` and `include_policy!`, from the `strig-macros` crate, validate the policy at compile time: a policy that does not validate does not build. They live in their own crate rather than behind a `strig` feature; the guide explains [why](docs/dsl.md#macros).

```rust
use strig_macros::{include_policy, policy};

let inline: strig::dsl::Policy = policy!(r#"
language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
"#);
let from_file: strig::dsl::Policy = include_policy!("policies/main.strig");
```

## Inspector (`strig-inspect`)

`strig-inspect` shows why a decision came out the way it did. It is built on `Engine::explain`, which Rust and JS can also call directly. From the example scenario:

```sh
strig-inspect explain --scenario crates/strig-inspect/examples/scenario.json \
    --subject ben --permission document.view --resource secret
```

```text
DENIED — ben asks document.view on document:secret → project:roadmap → org:acme → global
reason: grant no-secret (document.view, step 0) chosen by strategy most_specific
permissions that grant: document.view, project.view
effective roles: member
override resource_owner: abstained
grants (5):
  + members-view allow project.view → role member on org [step 2]
      candidate
  - editors-edit allow project.edit → relation editor on project
      permission not related
  ★ no-secret deny document.view → any subject on document:secret [step 0]
      candidate
  - pro-export allow document.export → role member on org
      permission not related
  - no-invoice-export deny document.invoice.export → role member on doc_type:invoice
      permission not related
```

The crate is not on crates.io and is outside the workspace `default-members`. Install it from a clone:

```sh
cargo install --path crates/strig-inspect                          # window and terminal commands
cargo install --path crates/strig-inspect --no-default-features    # terminal commands only, no gpui
```

```sh
strig-inspect --scenario scenario.json --audit trail.jsonl          # window
strig-inspect --scenario scenario.json --subject ben --permission document.export --resource invoice-7 \
               --disable pro-export --tab matrix                    # window opened on a selection and tab
strig-inspect matrix --scenario scenario.json --resource secret --disable no-secret --add grant.json
strig-inspect audit  --audit trail.jsonl --scenario scenario.json
strig-inspect fmt [--check] <file|dir>
```

A scenario is a JSON file with the policy (`spec`, an `EngineSpec`), the data (`grants`, `tuples`, `env`) and the named subjects and resources to examine. The example in `crates/strig-inspect/examples/` comes with a forensic trail of six decisions, `audit.jsonl`, generated by:

```sh
cargo run -p strig-inspect --no-default-features --example trail -- \
    crates/strig-inspect/examples/scenario.json > crates/strig-inspect/examples/audit.jsonl
```

The window has three tabs:

- **Evaluation:** pick a subject, permission and resource and see the decision, the reason, the resource path with the deciding step, the effective roles, each override, and why each grant did or did not apply, with its condition tree and the resolved values.
- **Matrix:** every catalog permission for every subject on one resource. Click a cell to open its trace.
- **Audit:** reads a JSON Lines trail, checks the hash chain of the `forensic` records, shows the recorded trace and re-evaluates `detailed` and `forensic` decisions against the current policy, flagging the ones that would change.

**Simulation** works across the tabs: turn grants off or on, or add some with `--add`, and see whether the set would allow the access. When a decision changes, the original decision is shown next to it, and changed matrix cells are marked.

Files reload when they change on disk. The window follows the system light or dark appearance, uses the playground's palette, and embeds its fonts (Noto Sans and JetBrains Mono, OFL) and icons, so it looks the same on any machine. The interface is in English.

## Extension points

| Trait | Implement it to |
|---|---|
| `GrantSource` | Read grants from a database, a cache, or several sources (`(A, B)` tuples chain). |
| `TupleStore` | Keep ReBAC tuples outside memory. |
| `Override` | Decide before the grants: owner, superadmin, suspended account, maintenance window. `FnOverride` takes a closure. |
| `Strategy` | Combine grants with another rule. |
| `Invariant` | Add a rule for grant changes. |
| `CatalogRule` | Validate the catalog your way (`RequireMeta`, `FnRule`). |
| `AuditSink` | Send the audit trail somewhere else. |
| `Transport` | Carry change notices between instances. |
| `CapabilityProvider`, `GrantLoader` | Control how a session computes the capabilities it sends. |
| `ChangeSink` | React synchronously to each change (cache, metric). |

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --exclude strig-inspect --all-targets -- -D warnings
cargo test --workspace --exclude strig-inspect
cargo test -p strig-inspect --no-default-features

# transports against real servers (skipped without the variables)
STRIG_REDIS_URL=redis://127.0.0.1:6379/ STRIG_PG_URL=postgres://postgres:pw@127.0.0.1/postgres \
    cargo test --workspace --exclude strig-inspect
```

The npm package lives in `crates/strig-node/js`. `crates/strig-node/scripts/build.sh` builds the native module (`js/native/strig.<platform>-<arch>.node`, the local-build fallback of the loader) and the WebAssembly (`js/wasm/`); the release splits the native modules into per-platform packages with `scripts/package-platforms.mjs`; the wasm part needs the `wasm32-unknown-unknown` target and `wasm-bindgen-cli` 0.2.130.

```sh
sh crates/strig-node/scripts/build.sh
cd crates/strig-node/js
npm ci
npm test              # Node
npm run test:bun      # Bun
```

Set `STRIG_RUST_SERVER` to the URL of the `strig-axum` `server` example to also test the JS client against the Rust server.

To run the playground locally, see [`playground/README.md`](playground/README.md).

Building the `strig-inspect` window on Linux needs the Wayland and X11 development libraries, for example `libxkbcommon-dev`, `libwayland-dev`, `libxcb1-dev` and `libvulkan-dev`.

Benchmarks: `cargo bench -p strig --bench engine`, and `node bench/bench.mjs` in `crates/strig-node/js` (or `bun`); see [docs/benchmarks.md](docs/benchmarks.md).

Source comments are in Brazilian Portuguese. Issues and pull requests are welcome in English or Portuguese; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). The fonts embedded in `strig-inspect` are under the SIL Open Font License 1.1 (see `crates/strig-inspect/assets/fonts`).
