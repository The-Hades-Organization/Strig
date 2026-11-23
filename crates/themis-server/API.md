# Themis decision server: HTTP contract

All bodies are JSON (`Content-Type: application/json`). All times are milliseconds since the Unix epoch, UTC.
The server decides with its own clock. The contract has no authentication and no rate limiting: put the server
behind the embedder's gateway.

## Fail-closed rule

Any answer other than a successful `200` from a decision route means **no access**. A client must treat a
network error, a timeout, any `5xx` and any unreadable `2xx` as a deny. The server never answers a decision it could
not compute: it answers `503`.

## Errors

```json
{"error": {"code": "source_unavailable", "message": "the grant source is unavailable; access is denied"}}
```

`code` is stable and safe to branch on. `message` is fixed per code and never carries table names, paths or driver
text; those stay in the server log.

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `malformed_json` | The body is not JSON. |
| 400 | `invalid_request` | Valid JSON that does not fit the route, an unknown field, or a bad deadline header. |
| 400 | `batch_too_large` | More checks than the server's batch limit (default 256). |
| 400 | `too_many_resources` | More candidate resources than the limit (default 1000). |
| 404 | `not_found` | No such route. |
| 405 | `method_not_allowed` | Wrong method. |
| 413 | `body_too_large` | Body over the limit (default 1 MiB). |
| 415 | `unsupported_media_type` | Body is not `application/json`. |
| 503 | `source_unavailable` | The grants or the policy could not be loaded. |
| 503 | `query_limit_exceeded` | The query went past the server's `QueryLimits`. |
| 503 | `relation_depth_exceeded` | A relation chain was too deep to read a deny. |
| 503 | `deadline_exceeded` | The deadline passed before an answer was ready. |
| 503 | `clock_unavailable` | The server clock has no usable instant. |
| 503 | `internal` | Anything else that went wrong inside the server. |

`4xx` means the caller's request is wrong and retrying it unchanged will fail again. `503` means the server could not
decide: deny, and retry later.

## Deadline

Send `x-themis-timeout-ms: <positive integer>` to set the deadline of one request. Without it the server uses its
default (2 s). The server caps the value at its ceiling (default 10 s). `0`, a negative number or text is `400
invalid_request`. When the deadline passes the answer is `503 deadline_exceeded`.

## Routes

### `POST /v1/check`

```json
{"subject": {...}, "permission": "document.view", "resource": {...}, "env": {}, "at": 1700000000000}
```

`subject` and `resource` use the JSON of the Themis `Subject` and `Resource` types. `env` (optional) carries attributes
for conditions; its `now` is replaced by the server clock. `at` (optional) is what the caller thinks the time is, kept for
audit: it is echoed and never used to decide.

Answer `200`:

```json
{"decision": {"effect": "allow", ...}, "evaluated_at": 1700000000000, "requested_at": 1700000000000}
```

`decision.effect` is `allow` or `deny`. A deny is a normal `200`.

### `POST /v1/check/batch`

Body `{"checks": [<check>, ...]}`. Answer `{"results": [<check answer>, ...]}`, one per check, in request order. The
batch is all or nothing: if the server cannot answer, the whole call is an error and no result is partial.

### `POST /v1/list`

Body: `subject`, `permission`, `kind`, optional `layout` (path steps, most specific first), optional `resources`
(candidates), `env`, `at`.

Answer: `kind`, `permission`, `exact`, `shape`, `residual`, `warnings`, `evaluated_at`, and `ids` when `resources` was
sent. `shape.type` is one of `nothing`, `kind` (with `except`), `ids`, `within` (with `anchors`), `compound` (with
`expr`). `residual` lists what only the resource can settle: **never read it as an allow**. `ids` are the candidates the
subject reaches, with the undecided ones settled by a real check.

### `POST /v1/who`

Body: `permission`, optional `resource`, `env`, `at`. With `resource` it answers who holds the permission on it
(`who_can_on`); without, who is named by an allow grant anywhere (`who_can`).

Answer: `permission`, `entries` (each with a `subject` tagged by `type`: `user`, `object`, `role`, `principal`,
`userset`, `wildcard`, `anyone`, and the `via` that grants it), `except`, `evaluated_at`.

### `POST /v1/access`

Body: `resource`, `env`, `at`. Answer: who holds which permission on the resource (`access_of`), with the path that
decided each one.

### `GET /health/live`

`200 {"status":"live"}` while the process runs.

### `GET /health/ready`

`200 {"status":"ready"}` when the grant source answers. Otherwise `503` with the error body above, so an instance that
cannot load grants leaves the pool instead of denying everything.

## Client behavior (Rust, feature `client`)

* Every call has a timeout, sent to the server as the deadline header.
* The circuit breaker opens after N consecutive failures (network error, timeout, `5xx`), refuses calls for a wait, then lets one probe through. A successful probe closes it, a failed one reopens it. `4xx` does not count.
* A failed check is `Denied(Failure)` with a typed reason: `CircuitOpen`, `Timeout`, `Unreachable`, `Server`, `Rejected`, `InvalidResponse`.
* A batch is one call; the answers keep the request order. If the call fails, every check is denied with the same reason.
* `list`, `who` and `access` have no deny to fall back on: they return `Err(Failure)` and the caller must not list or show anything.
