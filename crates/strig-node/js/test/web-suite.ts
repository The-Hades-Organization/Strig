// Suite shared by the three web integrations. Each framework file gives `mount(options)`, which returns
// `{ call(user, id) -> { status, body }, close() }`. No external network: the decision server is an in-process fake.
import assert from 'node:assert/strict';
import http from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Grant, Subject } from '../dist/index.js';
import { RemoteClient } from '../dist/remote.js';
import { load, scopeFromString } from '../dist/node.js';

export function harness(label: string) {
  let failures = 0;
  return {
    async test(name: string, fn: () => Promise<unknown> | unknown): Promise<void> {
      try {
        await fn();
        console.log(`ok - ${label}: ${name}`);
      } catch (error) {
        failures += 1;
        process.exitCode = 1;
        console.log(`not ok - ${label}: ${name}\n  ${(error as Error | undefined)?.stack ?? error}`);
      }
    },
    get failures() {
      return failures;
    },
  };
}

/** In-process decision server. `handler(req, body, res)` may answer itself; `calls` counts what arrived. */
export interface FakeServer extends http.Server {
  calls: Array<{ url: string | undefined; headers: IncomingMessage['headers']; body: any }>;
  base: string;
  stop: () => Promise<void>;
}

export async function fakeServer(handler: (req: IncomingMessage, body: any, res: ServerResponse) => void): Promise<FakeServer> {
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', () => {
      fake.calls.push({ url: req.url, headers: req.headers, body: raw ? JSON.parse(raw) : undefined });
      handler(req, raw ? JSON.parse(raw) : undefined, res);
    });
  });
  const fake = server as FakeServer;
  fake.calls = [];
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  fake.base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  fake.stop = () => new Promise<void>((resolve) => (server.closeAllConnections(), server.close(() => resolve())));
  return fake;
}

export const reply = (res: ServerResponse, status: number, payload: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(payload));
};
export const allow = { decision: { effect: 'allow' }, evaluated_at: 1 };
export const deny = { decision: { effect: 'deny' }, evaluated_at: 1 };

const SPEC = {
  catalog: {
    targetKinds: ['project', 'document'],
    broadTargets: ['org'],
    permissions: [
      { key: 'project.view', targets: ['project'] },
      { key: 'project.edit', targets: ['project'] },
      { key: 'document.view', targets: ['project', 'document'], impliedBy: ['project.view'] },
    ],
  },
};
const memberGrant: Grant = { id: 'g1', subject: { kind: 'role', id: 'member' }, permission: 'project.view', target: { kind: 'project' }, effect: 'allow' };
const NOW = 1_700_000_000_000;

export const subjectOf = (req: { headers?: Record<string, string | string[] | undefined> }): Subject | undefined => {
  const id = (req.headers ?? {})['x-user'] as string | undefined;
  if (id === 'boom') throw new Error('secret detail from the extractor');
  return id ? { kind: 'user', id, roles: [{ role: 'member' }] } : undefined;
};
export const resourceOf = (req: { params: { id: string } }) => scopeFromString(`document:${req.params.id}/project:p1/org:o1`);

export async function localMode() {
  const { Engine, Context } = await load();
  return { engine: new Engine(SPEC), context: new Context({ grants: [memberGrant] }), now: () => NOW };
}

export interface MountedApp {
  call(user: string | undefined, id: string): Promise<{ status: number; body: any; handlerRan?: boolean }>;
  close(): Promise<unknown> | unknown;
}

export async function runSuite(label: string, mount: (options: Record<string, any>) => Promise<MountedApp>) {
  const { test } = harness(label);
  const base = { subject: subjectOf, resource: resourceOf };
  const use = async (options: Record<string, any>, fn: (app: MountedApp) => Promise<unknown>) => {
    const app = await mount({ ...base, ...options });
    try {
      await fn(app);
    } finally {
      await app.close();
    }
  };

  await test('local: allow passes the request', () =>
    localMode().then((local) => use({ permission: 'document.view', local }, async (app) => assert.equal((await app.call('ana', 'd1')).status, 200))));

  await test('local: deny answers 403 with the stable body', async () => {
    const local = await localMode();
    await use({ permission: 'project.edit', local }, async (app) => {
      const res = await app.call('ana', 'd1');
      assert.equal(res.status, 403);
      assert.equal(res.body.error.code, 'forbidden');
      assert.equal(res.handlerRan, false);
    });
  });

  await test('local: statuses are configurable', async () => {
    const local = await localMode();
    await use({ permission: 'project.edit', local, denyStatus: 404 }, async (app) => assert.equal((await app.call('ana', 'd1')).status, 404));
  });

  await test('an extractor that throws is a 500 with no detail, never a pass', async () => {
    const local = await localMode();
    const seen: string[] = [];
    await use({ permission: 'document.view', local, onError: (e: Error) => seen.push(e.message) }, async (app) => {
      const res = await app.call('boom', 'd1');
      assert.equal(res.status, 500);
      assert.equal(res.handlerRan, false);
      assert.ok(!JSON.stringify(res.body).includes('secret'));
    });
    assert.deepEqual(seen, ['secret detail from the extractor']);
  });

  await test('no subject answers 401', async () => {
    const local = await localMode();
    await use({ permission: 'document.view', local }, async (app) => assert.equal((await app.call(undefined, 'd1')).status, 401));
  });

  await test('remote: allow and deny follow the server', async () => {
    const server = await fakeServer((req, body, res) => reply(res, 200, body.subject.id === 'ana' ? allow : deny));
    try {
      const remote = new RemoteClient({ url: server.base });
      await use({ permission: 'document.view', remote }, async (app) => {
        assert.equal((await app.call('ana', 'd1')).status, 200);
        assert.equal((await app.call('bia', 'd1')).status, 403);
      });
      assert.equal(server.calls[0]?.url, '/v1/check');
      assert.equal(server.calls[0]?.body.permission, 'document.view');
    } finally {
      await server.stop();
    }
  });

  await test('remote: a server that is down answers 503, never an allow', async () => {
    const server = await fakeServer(() => {});
    const url = server.base;
    await server.stop();
    await use({ permission: 'document.view', remote: new RemoteClient({ url }) }, async (app) => {
      const res = await app.call('ana', 'd1');
      assert.equal(res.status, 503);
      assert.equal(res.body.error.code, 'source_unavailable');
      assert.equal(res.handlerRan, false);
    });
  });

  await test('remote: a 5xx, a non-200 and a garbled 200 are 503', async () => {
    for (const answer of [
      (res: ServerResponse) => reply(res, 500, { error: { code: 'internal', message: 'x' } }),
      (res: ServerResponse) => reply(res, 204, {}),
      (res: ServerResponse) => (res.writeHead(200), res.end('not json')),
    ]) {
      const server = await fakeServer((req, body, res) => answer(res));
      try {
        await use({ permission: 'document.view', remote: new RemoteClient({ url: server.base }) }, async (app) => assert.equal((await app.call('ana', 'd1')).status, 503));
      } finally {
        await server.stop();
      }
    }
  });

  await test('remote: a 4xx from the server is a 500 with the stable body and the server text is not echoed', async () => {
    const server = await fakeServer((req, body, res) => reply(res, 400, { error: { code: 'invalid_request', message: 'secret server text' } }));
    try {
      await use({ permission: 'document.view', remote: new RemoteClient({ url: server.base }) }, async (app) => {
        const res = await app.call('ana', 'd1');
        assert.equal(res.status, 500);
        assert.equal(res.handlerRan, false);
        assert.ok(!JSON.stringify(res.body).includes('secret'));
      });
    } finally {
      await server.stop();
    }
  });

  await test('an extractor that returns a promise is refused, never a pass', async () => {
    const local = await localMode();
    await use({ permission: 'document.view', local, subject: async (req: Parameters<typeof subjectOf>[0]) => subjectOf(req) }, async (app) => {
      const res = await app.call('ana', 'd1');
      assert.equal(res.status, 500);
      assert.equal(res.handlerRan, false);
    });
  });

  await test('remote: a call that outlives the timeout is 503', async () => {
    const server = await fakeServer(() => {});
    try {
      await use({ permission: 'document.view', remote: new RemoteClient({ url: server.base, timeoutMs: 40 }) }, async (app) => assert.equal((await app.call('ana', 'd1')).status, 503));
    } finally {
      await server.stop();
    }
  });

  await test('remote: an open circuit refuses without calling the server, and the status is configurable', async () => {
    const server = await fakeServer((req, body, res) => reply(res, 503, { error: { code: 'overloaded', message: 'x' } }));
    try {
      const remote = new RemoteClient({ url: server.base, breaker: { failureThreshold: 2, waitMs: 60_000, clock: () => 0 } });
      await use({ permission: 'document.view', remote, failureStatus: 502 }, async (app) => {
        await app.call('ana', 'd1');
        await app.call('ana', 'd1');
        assert.equal((await app.call('ana', 'd1')).status, 502);
      });
      assert.equal(server.calls.length, 2);
    } finally {
      await server.stop();
    }
  });
}
