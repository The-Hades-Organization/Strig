// Remote client and breaker tests: injected clock and fetch, so no real waiting. `run.mjs` imports this file.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { CircuitBreaker, RemoteClient, messageFor, parseErrorCode } from '../remote.js';
import { MissingPeerError, createAuthorizer, requirePeer } from '../web-core.js';
import { allow, deny, fakeServer, harness, localMode, reply, subjectOf, resourceOf } from './web-suite.mjs';

const { test } = harness('web');
const input = (id) => ({ subject: { kind: 'user', id }, permission: 'document.view', resource: { path: [] } });
const answer = (status, payload) => async () => new Response(JSON.stringify(payload), { status });

await test('breaker: opens after the threshold, waits, then lets exactly one probe through', () => {
  let t = 0;
  const b = new CircuitBreaker({ failureThreshold: 2, waitMs: 100, clock: () => t });
  b.failure(b.acquire());
  b.failure(b.acquire());
  assert.equal(b.state, 'open');
  assert.equal(b.acquire(), null);
  t = 99;
  assert.equal(b.acquire(), null);
  t = 100;
  const probe = b.acquire();
  assert.equal(probe.probe, true);
  assert.equal(b.state, 'half-open');
  assert.equal(b.acquire(), null, 'only one probe');
  b.success(probe);
  assert.equal(b.state, 'closed');
  assert.notEqual(b.acquire(), null);
});

await test('breaker: a failed probe reopens and the wait restarts', () => {
  let t = 0;
  const b = new CircuitBreaker({ failureThreshold: 1, waitMs: 100, clock: () => t });
  b.failure(b.acquire());
  t = 100;
  b.failure(b.acquire());
  assert.equal(b.state, 'open');
  t = 150;
  assert.equal(b.acquire(), null);
  t = 200;
  assert.equal(b.acquire().probe, true);
});

await test('breaker: a late success from an old generation does not close the circuit', () => {
  const b = new CircuitBreaker({ failureThreshold: 1, waitMs: 100, clock: () => 0 });
  const slow = b.acquire();
  b.failure(b.acquire());
  assert.equal(b.state, 'open');
  b.success(slow);
  assert.equal(b.state, 'open');
});

await test('breaker: a late failure from an old generation does not reopen a closed circuit', () => {
  let t = 0;
  const b = new CircuitBreaker({ failureThreshold: 1, waitMs: 10, clock: () => t });
  const slow = b.acquire();
  b.failure(b.acquire());
  t = 10;
  b.success(b.acquire());
  assert.equal(b.state, 'closed');
  b.failure(slow);
  assert.equal(b.state, 'closed');
});

await test('breaker: rejects a non-positive setting', () => {
  assert.throws(() => new CircuitBreaker({ failureThreshold: 0 }), TypeError);
  assert.throws(() => new CircuitBreaker({ waitMs: -1 }), TypeError);
});

await test('client: a 4xx is a deny that does not count against the circuit', async () => {
  const client = new RemoteClient({ url: 'http://x', fetch: answer(400, { error: { code: 'invalid_request', message: 'm' } }), breaker: { failureThreshold: 1 } });
  const result = await client.check(input('ana'));
  assert.equal(result.allowed, false);
  assert.equal(result.failure.reason, 'rejected');
  assert.equal(result.failure.code, 'invalid_request');
  assert.equal(client.breaker.state, 'closed');
});

await test('client: an unknown error code does not break decoding', async () => {
  const client = new RemoteClient({ url: 'http://x', fetch: answer(503, { error: { code: 'from_the_future', message: 'm' } }) });
  const result = await client.check(input('ana'));
  assert.equal(result.allowed, false);
  assert.deepEqual(result.failure.code, { unknown: 'from_the_future' });
  assert.deepEqual(parseErrorCode(7), { unknown: '' });
});

await test('client: only a 200 is a success', async () => {
  for (const status of [201, 204, 302, 404, 500]) {
    const result = await new RemoteClient({ url: 'http://x', fetch: answer(status, allow) }).check(input('ana'));
    assert.equal(result.allowed, false, `status ${status}`);
  }
  assert.equal((await new RemoteClient({ url: 'http://x', fetch: answer(200, { decision: { effect: 'maybe' } }) }).check(input('ana'))).failure.reason, 'invalid_response');
});

await test('client: half-open probe through the client closes the circuit again', async () => {
  let t = 0;
  let status = 500;
  const fetch = async () => new Response(JSON.stringify(status === 200 ? allow : {}), { status });
  const client = new RemoteClient({ url: 'http://x', fetch, breaker: { failureThreshold: 2, waitMs: 1000, clock: () => t } });
  await client.check(input('a'));
  await client.check(input('a'));
  assert.equal((await client.check(input('a'))).failure.reason, 'circuit_open');
  t = 1000;
  status = 200;
  assert.equal((await client.check(input('a'))).allowed, true);
  assert.equal(client.breaker.state, 'closed');
});

await test('client: a late answer from before the circuit opened does not close it', async () => {
  let release;
  const gate = new Promise((resolve) => (release = resolve));
  let n = 0;
  const fetch = async () => {
    n += 1;
    if (n === 1) {
      await gate;
      return new Response(JSON.stringify(allow), { status: 200 });
    }
    return new Response('{}', { status: 500 });
  };
  const client = new RemoteClient({ url: 'http://x', fetch, breaker: { failureThreshold: 1, waitMs: 1000, clock: () => 0 } });
  const late = client.check(input('a'));
  await client.check(input('b'));
  assert.equal(client.breaker.state, 'open');
  release();
  assert.equal((await late).allowed, true, 'the call itself keeps its own answer');
  assert.equal(client.breaker.state, 'open');
});

await test('client: batch is one call and keeps the order', async () => {
  const server = await fakeServer((req, body, res) => reply(res, 200, { results: body.checks.map((c) => (c.subject.id === 'ana' ? allow : deny)) }));
  try {
    const client = new RemoteClient({ url: server.base });
    const results = await client.checkBatch([input('ana'), input('bia'), input('ana')]);
    assert.deepEqual(results.map((r) => r.allowed), [true, false, true]);
    assert.equal(server.calls.length, 1);
    assert.equal(server.calls[0].url, '/v1/check/batch');
    assert.equal(server.calls[0].headers['x-strig-timeout-ms'], '2000');
    assert.deepEqual(await client.checkBatch([]), []);
    assert.equal(server.calls.length, 1, 'an empty batch makes no call');
  } finally {
    await server.stop();
  }
});

await test('client: a failed or short batch denies every check', async () => {
  const wrongSize = new RemoteClient({ url: 'http://x', fetch: answer(200, { results: [allow] }) });
  assert.deepEqual((await wrongSize.checkBatch([input('a'), input('b')])).map((r) => r.allowed), [false, false]);
  const down = new RemoteClient({ url: 'http://x', fetch: answer(503, {}) });
  const results = await down.checkBatch([input('a'), input('b')]);
  assert.deepEqual(results.map((r) => r.failure.reason), ['server', 'server']);
});

await test('client: a call that outlives the timeout is aborted and denied', async () => {
  const fetch = (url, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(new Error('aborted'))));
  const result = await new RemoteClient({ url: 'http://x', fetch, timeoutMs: 10 }).check(input('a'));
  assert.equal(result.failure.reason, 'timeout');
});

await test('authorizer: needs exactly one mode and a subject function', async () => {
  const local = await localMode();
  assert.throws(() => createAuthorizer({ subject: subjectOf, resource: resourceOf }), TypeError);
  assert.throws(() => createAuthorizer({ subject: subjectOf, local, remote: new RemoteClient({ url: 'http://x' }) }), TypeError);
  assert.throws(() => createAuthorizer({ local }), TypeError);
});

await test('authorizer: checkFor mode decides through the binding', async () => {
  const local = { ...(await localMode()), checkFor: true };
  const decide = createAuthorizer({ subject: subjectOf, resource: resourceOf, permission: 'document.view', local });
  const request = { headers: { 'x-user': 'ana' }, params: { id: 'd1' } };
  assert.equal((await decide(request)).kind, 'allow');
  assert.equal((await decide(request, { permission: 'project.edit' })).status, 403);
});

await test('requirePeer: a missing framework names what to install', () => {
  assert.throws(() => requirePeer('strig-no-such-framework', 'express'), (error) => {
    assert.ok(error instanceof MissingPeerError);
    assert.match(error.message, /npm install strig-no-such-framework/);
    return true;
  });
});

await test('requirePeer: a broken peer or a missing transitive dependency is rethrown, not called "not installed"', () => {
  const broken = Object.assign(new SyntaxError('Unexpected token'), {});
  assert.throws(() => requirePeer('express', 'express', () => { throw broken; }), (error) => error === broken);
  const transitive = Object.assign(new Error("Cannot find module 'accepts'"), { code: 'MODULE_NOT_FOUND' });
  assert.throws(() => requirePeer('express', 'express', () => { throw transitive; }), (error) => error === transitive);
});

await test('the three subpaths import without a framework call and can be require()d from CommonJS', async () => {
  if (!process.features.require_module) return; // require() of ESM needs Node 22.12 or 20.19
  const run = promisify(execFile);
  const { stdout } = await run(process.execPath, [fileURLToPath(new URL('./require-subpaths.cjs', import.meta.url))]);
  assert.equal(stdout.trim(), 'ok');
});

await test('client: a 3xx is a failure and is never followed', async () => {
  const target = await fakeServer((req, body, res) => reply(res, 200, allow));
  const gateway = await fakeServer((req, body, res) => {
    res.writeHead(302, { location: `${target.base}/v1/check` });
    res.end();
  });
  try {
    const client = new RemoteClient({ url: gateway.base, headers: { 'x-api-key': 'k' }, breaker: { failureThreshold: 1 } });
    const result = await client.check(input('ana'));
    assert.equal(result.allowed, false);
    assert.equal(result.failure.reason, 'unexpected_status');
    assert.equal(result.failure.status, 302);
    assert.equal(target.calls.length, 0, 'the redirect target is never called, and never sees the headers');
    assert.equal(client.breaker.state, 'open', 'a 3xx counts against the circuit');
  } finally {
    await gateway.stop();
    await target.stop();
  }
});

await test('client: the deadline holds when fetch ignores the signal, and the probe is freed', async () => {
  let t = 0;
  let hang = true;
  const fetch = (url, init) => (hang ? new Promise(() => {}) : Promise.resolve(new Response(JSON.stringify(allow), { status: 200 })));
  const client = new RemoteClient({ url: 'http://x', fetch, timeoutMs: 10, breaker: { failureThreshold: 1, waitMs: 100, clock: () => t } });
  assert.equal((await client.check(input('a'))).failure.reason, 'timeout');
  assert.equal(client.breaker.state, 'open');
  t = 100;
  assert.equal((await client.check(input('a'))).failure.reason, 'timeout', 'the probe times out too');
  assert.equal(client.breaker.state, 'open', 'a failed probe reopens, it does not stay half-open');
  t = 200;
  hang = false;
  assert.equal((await client.check(input('a'))).allowed, true);
  assert.equal(client.breaker.state, 'closed');
});

await test('client: the timer is cleared on every path', async () => {
  const realSet = globalThis.setTimeout;
  const realClear = globalThis.clearTimeout;
  const live = new Set();
  let capture = false; // the client sets its timer synchronously inside check(); other suites run concurrently and set their own
  globalThis.setTimeout = (fn, ...rest) => {
    const id = realSet(() => { live.delete(id); fn(); }, ...rest);
    if (capture) live.add(id);
    return id;
  };
  globalThis.clearTimeout = (id) => { live.delete(id); realClear(id); };
  const run = (options) => {
    capture = true;
    const pending = new RemoteClient({ url: 'http://x', ...options }).check(input('a'));
    capture = false;
    return pending;
  };
  try {
    await run({ fetch: answer(200, allow) });
    await run({ fetch: async () => { throw new Error('down'); } });
    await run({ fetch: () => new Promise(() => {}), timeoutMs: 5 });
    assert.equal(live.size, 0);
  } finally {
    globalThis.setTimeout = realSet;
    globalThis.clearTimeout = realClear;
  }
});

await test('client: a payload that does not serialize denies without touching the circuit or the server', async () => {
  let calls = 0;
  const client = new RemoteClient({ url: 'http://x', fetch: async () => (calls += 1, new Response(JSON.stringify(allow))), breaker: { failureThreshold: 1 } });
  const cyclic = {};
  cyclic.self = cyclic;
  for (const env of [{ n: 1n }, cyclic]) {
    const result = await client.check({ ...input('a'), env });
    assert.equal(result.allowed, false);
    assert.equal(result.failure.reason, 'invalid_request');
  }
  assert.equal(calls, 0);
  assert.equal(client.breaker.state, 'closed');
  assert.equal((await client.check(input('a'))).allowed, true);
});

await test('client: a probe answered by a gateway 4xx counts as a failed probe', async () => {
  let t = 0;
  let status = 500;
  const fetch = async () => new Response('', { status });
  const client = new RemoteClient({ url: 'http://x', fetch, breaker: { failureThreshold: 1, waitMs: 100, clock: () => t } });
  await client.check(input('a'));
  t = 100;
  status = 404;
  assert.equal((await client.check(input('a'))).failure.reason, 'rejected');
  assert.equal(client.breaker.state, 'open', 'the circuit did not close');
  t = 200;
  status = 200;
});

await test('client: a probe answered by a 4xx with an error body is neutral: still half-open, probe free', async () => {
  let t = 0;
  let status = 500;
  let payload = {};
  const fetch = async () => new Response(JSON.stringify(payload), { status });
  const client = new RemoteClient({ url: 'http://x', fetch, breaker: { failureThreshold: 1, waitMs: 100, clock: () => t } });
  await client.check(input('a'));
  t = 100;
  status = 400;
  payload = { error: { code: 'invalid_request', message: 'm' } };
  assert.equal((await client.check(input('a'))).failure.reason, 'rejected');
  assert.equal(client.breaker.state, 'half-open');
  assert.equal(client.breaker.probing, false);
  status = 200;
  payload = allow;
  assert.equal((await client.check(input('a'))).allowed, true, 'the next call is the probe');
  assert.equal(client.breaker.state, 'closed');
});

await test('client: a 4xx does not reset the count of 5xx in a row', async () => {
  const statuses = [500, 500, 400, 500];
  const fetch = async () => { const s = statuses.shift(); return new Response(JSON.stringify(s === 400 ? { error: { code: 'invalid_request', message: 'm' } } : {}), { status: s }); };
  const client = new RemoteClient({ url: 'http://x', fetch, breaker: { failureThreshold: 3 } });
  for (let i = 0; i < 4; i += 1) await client.check(input('a'));
  assert.equal(client.breaker.state, 'open');
});

await test('client: two concurrent calls on a half-open circuit send one probe', async () => {
  let t = 0;
  let release;
  const gate = new Promise((resolve) => (release = resolve));
  let sent = 0;
  const fetch = async () => { sent += 1; if (sent > 1) { await gate; return new Response(JSON.stringify(allow), { status: 200 }); } return new Response('{}', { status: 500 }); };
  const client = new RemoteClient({ url: 'http://x', fetch, breaker: { failureThreshold: 1, waitMs: 100, clock: () => t } });
  await client.check(input('a'));
  t = 100;
  const probe = client.check(input('a'));
  const second = await client.check(input('a'));
  assert.equal(second.failure.reason, 'circuit_open');
  release();
  assert.equal((await probe).allowed, true);
  assert.equal(sent, 2);
});

await test('client: timeoutMs above the timer limit is refused; the batch failure objects are not shared', async () => {
  assert.throws(() => new RemoteClient({ url: 'http://x', timeoutMs: 2 ** 31 }), TypeError);
  const down = new RemoteClient({ url: 'http://x', fetch: answer(503, {}) });
  const [a, b] = await down.checkBatch([input('a'), input('b')]);
  assert.notEqual(a.failure, b.failure);
  await assert.rejects(down.checkBatch('x'), TypeError);
});

await test('authorizer: an onError that throws is still a refusal (503, stable body)', async () => {
  const decide = createAuthorizer({ subject: () => { throw new Error('x'); }, permission: 'p', resource: {}, remote: new RemoteClient({ url: 'http://x', fetch: answer(200, allow) }), onError: (e) => { throw e; } });
  const outcome = await decide({});
  assert.equal(outcome.kind, 'failure');
  assert.equal(outcome.status, 503);
  assert.equal(outcome.body.error.code, 'internal');
});

await test('authorizer: remote failures reach onError and keep the code apart', async () => {
  const seen = [];
  const make = (fetch, extra) => createAuthorizer({ subject: subjectOf, permission: 'p', resource: {}, remote: new RemoteClient({ url: 'http://x', fetch, ...extra }), onError: (e) => seen.push(e.failure.reason) });
  const req = { headers: { 'x-user': 'ana' } };
  assert.equal((await make(answer(400, { error: { code: 'invalid_request', message: 'm' } }))(req)).status, 500);
  assert.equal((await make(answer(503, { error: { code: 'overloaded', message: 'm' } }))(req)).body.error.code, 'overloaded');
  assert.equal((await make(() => new Promise(() => {}), { timeoutMs: 5 })(req)).body.error.code, 'deadline_exceeded');
  assert.equal((await make(answer(500, {}))(req)).body.error.code, 'source_unavailable');
  assert.deepEqual(seen, ['rejected', 'server', 'timeout', 'server']);
});

await test('authorizer: a bad status, an async subject and a non-client remote are refused', async () => {
  const base = { subject: subjectOf, resource: resourceOf, permission: 'p', local: await localMode() };
  for (const denyStatus of [200, 99, 600, 403.5, '403']) assert.throws(() => createAuthorizer({ ...base, denyStatus }), TypeError, String(denyStatus));
  assert.throws(() => createAuthorizer({ subject: subjectOf, remote: {} }), TypeError);
  const decide = createAuthorizer({ ...base, subject: async () => ({ kind: 'user', id: 'a' }) });
  assert.equal((await decide({ params: { id: 'd1' } })).kind, 'error');
  assert.equal((await createAuthorizer({ ...base, subject: async () => { throw new Error('x'); } })({ params: { id: 'd1' } })).kind, 'error');
});

await test('authorizer: an empty permission is an error, not a check', async () => {
  const decide = createAuthorizer({ subject: subjectOf, resource: resourceOf, local: await localMode() });
  const outcome = await decide({ headers: { 'x-user': 'ana' }, params: { id: 'd1' } }, { permission: '' });
  assert.equal(outcome.kind, 'error');
  assert.equal((await decide({ headers: { 'x-user': 'ana' }, params: { id: 'd1' } }, { permission: undefined })).kind, 'error');
});

await test('messageFor does not read inherited keys', () => {
  assert.equal(messageFor('constructor'), messageFor('internal'));
});
