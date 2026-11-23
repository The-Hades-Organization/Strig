// Remote client and breaker tests: injected clock and fetch, so no real waiting. `run.mjs` imports this file.
import assert from 'node:assert/strict';
import { CircuitBreaker, RemoteClient, parseErrorCode } from '../remote.js';
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
    assert.equal(server.calls[0].headers['x-themis-timeout-ms'], '2000');
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

await test('requirePeer: a missing framework names what to install', async () => {
  await assert.rejects(requirePeer('themis-no-such-framework', 'express'), (error) => {
    assert.ok(error instanceof MissingPeerError);
    assert.match(error.message, /npm install themis-no-such-framework/);
    return true;
  });
});
