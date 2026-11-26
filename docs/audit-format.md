# Audit record format and hash chain

This page is the contract of the `forensic` audit trail: what a record looks like byte for byte, how
its hash is computed, and how to chain and verify records from another language or in your own log.
The Rust code is the reference (`crates/strig/src/audit.rs`); the test
`canonical_vector_matches_the_document` fails if this page and the code drift apart.

## Canonical form

A record is one JSON object in **compact JSON** (no whitespace), encoded as UTF-8.

- **Key order is the order of the fields below**, not alphabetical. Nested objects follow the order
  stated for their type. Maps (`meta`, `attrs`) are written with keys in ascending byte order.
- **Absent fields are omitted**, never `null`: an optional field that is not set, an empty list
  (`violations`, `suggestions`, `roles`, `principals`) and an empty map (`meta`, `attrs`) do not
  appear. A level that does not keep a field leaves it out.
- **Strings** escape only `"` (`\"`), `\` (`\\`) and the control characters below U+0020 (`\b`, `\t`,
  `\n`, `\f`, `\r` for those five, `\u00XX` in lowercase hex for the rest). Everything else, including
  non-ASCII, is written as is in UTF-8 (`é`, not `é`). `/` is not escaped.
- **Integers** are written in decimal with no sign for positive values, no exponent, no fraction
  (`at` is an integer number of milliseconds since the Unix epoch).
- **Enums** are `snake_case` strings.

### Fields of an `AuditRecord`, in order

| # | Field | Type | Present |
|---|---|---|---|
| 1 | `at` | integer, ms since the Unix epoch | always |
| 2 | `level` | `minimal`, `standard`, `detailed`, `forensic` | always |
| 3 | `actor` | string, the actor id (its kind when anonymous) | always |
| 4 | `action` | `grant_add`, `grant_remove`, `tuple_add`, `tuple_remove`, `role_assign`, `role_revoke`, `decision`, `exclusive_acquire`, `exclusive_preempt`, `exclusive_release`, `exclusive_expire`, `mutation_propose`, `mutation_approve`, `mutation_reject`, `mutation_expire` | always |
| 5 | `object` | string: grant id, `object#relation@subject`, `role@subject` (`role#scope@subject` with a scope), or `permission@path` | always |
| 6 | `outcome` | `applied`, `rejected`, `allowed`, `denied`, `pending` | always |
| 7 | `grant` | grant summary | `standard`+ on a grant change |
| 8 | `role` | `{subject, role, scope?}` | `standard`+ on a role change |
| 9 | `violations` | list of strings | `standard`+ on a refusal |
| 10 | `suggestions` | list of suggestions | `standard`+ when an invariant proposed one |
| 11 | `decision` | decision summary | `standard`+ on a decision |
| 11b | `pending` | `{id, author, kind, target, expires_at?, reason?}`, the request of an approval-flow record | `standard`+ on `mutation_*` |
| 12 | `full_grant` | the whole grant | `detailed`+ on a grant change |
| 13 | `resource` | the whole resource | `detailed`+ on a decision |
| 14 | `explanation` | the full trace | `forensic` on a decision |
| 15 | `tuple` | the ReBAC tuple | `detailed`+ on a tuple change |
| 16 | `actor_detail` | the whole subject | `detailed`+ |
| 17 | `meta` | map of request metadata | `detailed`+, when not empty |
| 18 | `before_digest` | hex string | `forensic` |
| 19 | `after_digest` | hex string | `forensic` |
| 20 | `prev_hash` | hex string, hash of the previous record | `forensic`, omitted on the first record of a chain |
| 21 | `hash` | hex string | `forensic` |

The order of the nested types is the order of their declaration: a subject is `kind`, `id`, `roles`,
`principals`, `attrs`; a role assignment is `role` and then its scope and validity fields; a tuple is
`object`, `relation`, `subject`. The source of truth for the shape of `grant`, `explanation` and
the rest is the serialization of the Rust types (`serde`, in declaration order); the vector below
covers a tuple change with a subject, and the `forensic` records your own code produces round-trip
through `verifyAuditChain` / `verify_chain`, which re-serialize them in this order.

## Hash of the chain

At the `forensic` level each record carries `prev_hash`, the `hash` of the record before it, and its
own `hash`:

```
hash = lowercase_hex( SHA-256( canonical JSON of the record without the `hash` field ) )
```

The record is serialized with `prev_hash` already set and `hash` left out. Because `hash` is the last
field, a verifier in another language can take a record line as received, cut the trailing
`,"hash":"<64 hex>"` member and hash what is left (it already ends in `}`), with no need to model
every type. The first record of a chain has no `prev_hash`; one that resumes a chain (`resume_chain`,
`audit.prevHash`) carries the hash it continues.

Verification walks the records in the order they were written: each must have a `hash`, each from the
second on must carry a `prev_hash` equal to the `hash` before it, and each `hash` must match the
recomputation. An edited record is `Tampered`, a removed or reordered one makes the next `Broken`.

### The redacted version is what is hashed

Redaction (below) runs before `prev_hash` and `hash` are set: the hash covers the record **as it is
written**, with the sensitive values already masked, so a log that only ever holds the masked version
still verifies. `before_digest` and `after_digest` are computed from the grants before redaction and
carry no attribute.

### Test vector

Record before hashing (a `forensic` tuple change, one line, `prev_hash` of 64 `a`):

```json
{"at":1700000000000,"level":"forensic","actor":"alice","action":"tuple_add","object":"doc:d1#viewer@user:bob","outcome":"applied","tuple":{"object":{"kind":"doc","id":"d1"},"relation":"viewer","subject":{"object":{"kind":"user","id":"bob"}}},"actor_detail":{"kind":"user","id":"alice","roles":[{"role":"admin"}],"principals":["authenticated"]},"meta":{"ip":"203.0.113.42","reason":"ticket \"SUP-1\" é"},"prev_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

SHA-256 of exactly those bytes (UTF-8, no trailing newline):

```
087dbffda54667a64ae971f80c70bf6544b205be90c9ca9cc592ef113f4a4cb5
```

The record as written is the same object with `,"hash":"087dbffd…4cb5"` before the closing `}`. In a
shell: `printf '%s' '<the line above>' | sha256sum`.

## Only the records: chaining in your own log

You do not have to give Strig the destination. `apply` and `applyTemplate` return the records
(`audit` in JS and in `ApplyResult`, `audits` for a template, the `AuditRecord` the `Auditor` returns
in Rust); store them wherever you keep your log, in the order the changes were made.

- **Chain.** Pass `prevHash` (JS) or call `Auditor::resume_chain` (Rust) with the `hash` of the last
  record you stored, so the next record continues it. Keep one writer per chain, or serialize the
  calls: two records made from the same `prevHash` fork the chain.
- **Verify.** In Rust, `verify_chain(&records)`; in JS, `verifyAuditChain(records)`, which answers
  `{ ok: true, head }` or `{ ok: false, code, index }` with `code` one of `TAMPERED`, `BROKEN`,
  `UNCHAINED`, `ANCHOR_MISMATCH`, `HEAD_MISMATCH`. Verify with the records as stored; they are
  re-serialized in the canonical order, so it does not matter that a JavaScript object does not
  keep the order of the keys. Store `hash` and `prev_hash` as opaque strings and do not recompute
  them outside this page's rules.
- **Another language.** Reproduce the vector above, then follow the field order of the table. If you
  keep the JSON Lines text Strig wrote (`JsonLinesAudit`), the bytes of each line already are the
  canonical form and the cut-the-`hash` rule above verifies it with nothing but SHA-256.

## Anchoring the head of the chain

A chain proves that nothing was edited or removed from the middle. It cannot prove that the last
records were not cut off, because there is nothing after them to disagree. Publish the **head**, the
`hash` of the last record, somewhere the writer cannot rewrite: an external log, a signed timestamp, a
ticket. Strig takes no network dependency for this; it only gives you the value and checks against it.

- Rust: `Auditor::chain_head()` (the last record accepted) or `chain_head(&records)`; check with
  `verify_chain_anchored(&records, start, head)`.
- JS: the `hash` of the last `audit` returned, or `verifyAuditChain(records).head`; check with
  `verifyAuditChain(records, { start, head })`.

`head` fails with `HEAD_MISMATCH` if the sequence ends anywhere else, and `start` fails with
`ANCHOR_MISMATCH` if the first record does not continue the hash you know, which lets you verify a
segment (the records since the last anchor) instead of the whole log: the head you published last
time is the `start` of the next check.

## Redaction

`Auditor::with_redactor(mask_attributes(["ip", "email"], "[redacted]"))` (Rust) or
`audit: { redact: { keys: ['ip', 'email'], mask: '[redacted]' } }` (JS) replaces the value of those
attribute keys in `meta`, in the actor's and the resource's `attrs` and in their copies inside a
decision trace, before the record is hashed and written. A custom redactor
(`Auditor::with_redactor`, `hooks.auditRedact` in JS) can change anything else in the record. If it
fails the change is refused whatever the failure mode: the record is never written unmasked.
Redaction does not look inside the condition of a grant or in `object`; keep sensitive values out of
ids.

## When the sink fails

`closed` (the default) refuses the change with the `audit` violation: no record, no change.
`open` lets the change through and keeps the record in an in-memory retry queue:

- Records leave the queue in the order they entered, and nothing is written ahead of the record at
  the head: while it waits, every later record waits behind it, so the sink always sees the chain in
  order. A `closed` record made while others wait forces the queue to drain first and is refused if
  it cannot.
- The queue is bounded (`RetryPolicy::capacity`, default 1024) and retries back off from
  `base_delay_ms` (100) doubling up to `max_delay_ms` (30 000), counted on the auditor's clock.
  Retries happen on the next record or on `flush`.
- A full queue **drops the new record**, keeping the older ones in place. A dropped record is not
  part of the chain (the next record continues the last one that was accepted), so the chain of what
  was written still verifies; the gap is not visible to the verifier. It is reported instead: by
  `AuditStatus::Dropped`, by the `dropped` counter of `AuditStats` and by the `on_drop` callback
  (`onAuditDrop` in JS), which receives the whole record so you can keep it elsewhere.
- The queue lives in memory: records waiting when the process stops are lost. Flush before shutdown
  and treat `pending` as an alarm.

The mode of a record is the first of: the mode of the call (`GovernanceAt::fail_mode`,
`Auditor::grant_mutation_with`, `audit.failMode` in JS), the mode of its permission
(`Auditor::with_permission_fail_mode`, `auditPolicy.permissions` in JS), the auditor's default
(`with_fail_mode`, `auditPolicy.failMode`), `closed`. Role, tuple and exclusive-resource records
carry no permission, so they follow the call and the default. The result of an `apply` says where the
record went: `auditStatus` is `written`, `pending` or `dropped`.

## Approval flow records

The four `mutation_*` actions record the steps of a pending request (`Approvals` in Rust, `propose`,
`resolve` and `expire` in JS). `object` is the request id and `pending` names the request: its `author`
(the actor id of whoever proposed the change), the `kind` of the change (`add`, `remove`, `assign_role`,
`revoke_role`), its `target` (grant id, or `role@subject`), the optional `expires_at` and, on a refusal by
an approver, the `reason`. `outcome` says whether the step took effect:

| action | `actor` | `outcome` |
|---|---|---|
| `mutation_propose` | the author | `pending` when the request was kept, `rejected` when the invariants or the audit refused it |
| `mutation_approve` | the approver | `applied` when the change then went through the governance, `rejected` when the approver was the author, lacked the permission or the invariants now refuse it (`violations` says which) |
| `mutation_reject` | the approver | `applied` when the request was refused, `rejected` when the attempt was refused (`violations`) |
| `mutation_expire` | `strig-expiry` | `applied` |

An approval writes `mutation_approve` first and then the `grant_add`/`grant_remove`/`role_*` record of the
change itself, with the author as `actor` and the approver in `meta.approved_by` and the request id in
`meta.request_id` (kept from `detailed`). A request whose approval record exists and whose change record does
not was never applied.
