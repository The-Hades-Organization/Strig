import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import express from 'express';
import { authorize, createCan } from '../dist/express.js';
import type { AuthorizerOptions } from '../dist/express.js';
import { harness, localMode, resourceOf, runSuite, subjectOf } from './web-suite.js';

type WebReq = { headers?: Record<string, string | string[] | undefined>; params: { id: string } };

await runSuite('express', async (options) => {
  const app = express();
  let ran = false;
  app.get('/doc/:id', authorize<WebReq>(options as AuthorizerOptions<WebReq>), (req, res) => ((ran = true), res.json({ ok: true })));
  const server = await new Promise<Server>((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    async call(user: string | undefined, id: string) {
      ran = false;
      const res = await fetch(`${base}/doc/${id}`, { headers: user ? { 'x-user': user } : {} });
      return { status: res.status, body: await res.json(), handlerRan: ran };
    },
    close: () => new Promise<void>((resolve) => (server.closeAllConnections(), server.close(() => resolve()))),
  };
});

// Express 4 leaves a rejected middleware hanging, so nothing may escape: an onError that throws, or a response that fails, goes to next(error).
const { test } = harness('express');

await test('an onError that throws still refuses the request (503), and next is not called', async () => {
  const local = await localMode();
  const sent: unknown[] = [];
  const res = { status(s: number) { sent.push(s); return this; }, json(b: { error: { code: string } }) { sent.push(b.error.code); } };
  let nexted = 0;
  await authorize<WebReq>({ subject: subjectOf, resource: resourceOf, permission: 'document.view', local, onError: (e) => { throw e; } })({ headers: { 'x-user': 'boom' }, params: { id: 'd1' } }, res, () => (nexted += 1));
  assert.deepEqual(sent, [503, 'internal']);
  assert.equal(nexted, 0);
});

await test('a response that throws goes to next(error), never to next()', async () => {
  const local = await localMode();
  const res = { status() { return this; }, json(): never { throw new Error('socket'); } };
  const calls: unknown[][] = [];
  await authorize<WebReq>({ subject: subjectOf, resource: resourceOf, permission: 'project.edit', local })({ headers: { 'x-user': 'ana' }, params: { id: 'd1' } }, res, (...args: unknown[]) => calls.push(args));
  assert.equal(calls.length, 1);
  assert.ok(calls[0]![0] instanceof Error);
});

await test('can() refuses a missing permission up front and checks per route', async () => {
  const can = createCan<WebReq>({ subject: subjectOf, resource: resourceOf, local: await localMode() });
  assert.throws(() => can(undefined as unknown as string), TypeError);
  assert.throws(() => can(''), TypeError);
  let nexted = 0;
  await can('document.view')({ headers: { 'x-user': 'ana' }, params: { id: 'd1' } }, {} as unknown as Parameters<ReturnType<typeof can>>[1], () => (nexted += 1));
  assert.equal(nexted, 1);
});
