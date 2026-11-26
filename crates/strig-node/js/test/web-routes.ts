// The central route table: matching, deny by default, the three adapters and the audit helper.
import 'reflect-metadata';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import express from 'express';
import Fastify from 'fastify';
import { authorizeRoutes } from '../dist/express.js';
import { authorizeRoutes as fastifyAuthorize } from '../dist/fastify.js';
import { Can, StrigRouteGuard } from '../dist/nestjs.js';
import { compileRoutes } from '../dist/route-table.js';
import type { RouteRule } from '../dist/route-table.js';
import { assertRoutesCovered, auditRoutes, collectFastifyRoutes, expressRoutes, nestRoutes } from '../dist/testing.js';
import { harness, localMode, subjectOf } from './web-suite.js';
import { scopeFromString } from '../dist/node.js';

const { test } = harness('routes');
const docOf = (_req: unknown, params: Record<string, string>) => scopeFromString(`document:${params.id}/project:p1/org:o1`);

const table: RouteRule[] = [
  { method: 'GET', path: '/health', public: true },
  { method: 'GET', path: '/doc/:id', permission: 'document.view', resource: docOf },
  { method: ['PUT', 'DELETE'], path: '/doc/:id', permission: 'project.edit', resource: docOf },
  { method: '*', path: '/files/*', permission: 'document.view', resource: docOf },
];

await test('matching: params, wildcard, methods, HEAD, query, trailing slash', () => {
  const t = compileRoutes(table);
  assert.deepEqual(t.match('get', '/doc/d%201?x=1')?.params, { id: 'd 1' });
  assert.equal(t.match('GET', '/doc/d1/')?.rule.permission, 'document.view');
  assert.equal(t.match('HEAD', '/doc/d1')?.rule.permission, 'document.view');
  assert.equal(t.match('DELETE', '/doc/d1')?.rule.permission, 'project.edit');
  assert.equal(t.match('POST', '/doc/d1'), undefined);
  assert.equal(t.match('POST', '/files/a/b')?.params['*'], 'a/b');
  assert.equal(t.match('GET', '/files'), undefined);
  assert.equal(t.match('GET', '/doc//d1'), undefined);
  assert.equal(t.match('GET', '/doc/%E0%A4%A'), undefined);
  assert.equal(t.match('GET', '/Health'), undefined, 'paths are case sensitive');
  assert.equal(t.match('GET', 'http://host/health'), undefined);
});

await test('first rule wins', () => {
  const t = compileRoutes([{ method: 'GET', path: '/u/me', public: true }, { method: 'GET', path: '/u/:id', permission: 'a.b' }]);
  assert.equal(t.match('GET', '/u/me')?.rule.public, true);
  assert.equal(t.match('GET', '/u/x')?.rule.permission, 'a.b');
});

await test('a bad rule is refused at startup', () => {
  const bad = (rule: object) => assert.throws(() => compileRoutes([rule as RouteRule]), TypeError);
  bad({ method: 'GET', path: '/x' });
  bad({ method: 'GET', path: '/x', permission: 'a.b', public: true });
  bad({ method: 'GET', path: '/x', public: true, resource: {} });
  bad({ method: 'GET', path: 'x', public: true });
  bad({ method: '', path: '/x', public: true });
  bad({ method: [], path: '/x', public: true });
  bad({ method: 'GET', path: '/a/*/b', public: true });
  bad({ method: 'GET', path: '/a/:id?', public: true });
  bad({ method: 'GET', path: '/a/b-:id', public: true });
  assert.throws(() => compileRoutes(undefined as unknown as RouteRule[]), TypeError);
});

async function listen(app: ReturnType<typeof express>) {
  const server = await new Promise<Server>((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const get = async (path: string, user?: string, method = 'GET') => {
    const res = await fetch(base + path, { method, headers: user ? { 'x-user': user } : {} });
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  return { get, close: () => new Promise<void>((resolve) => (server.closeAllConnections(), server.close(() => resolve()))) };
}

function expressApp(options: object) {
  const app = express();
  app.use(authorizeRoutes({ subject: subjectOf, routes: table, ...options } as Parameters<typeof authorizeRoutes>[0]));
  const ok = (_req: unknown, res: { json(b: unknown): void }) => res.json({ ok: true });
  app.get('/health', ok);
  app.get('/doc/:id', ok);
  app.delete('/doc/:id', ok);
  app.get('/open', ok);
  return app;
}

await test('express: deny by default, public, allow, deny, unauthenticated, unknown URL', async () => {
  const server = await listen(expressApp({ local: await localMode() }));
  try {
    assert.equal((await server.get('/health')).status, 200, 'public needs no subject');
    assert.equal((await server.get('/doc/d1', 'ana')).status, 200);
    assert.equal((await server.get('/doc/d1')).status, 401);
    const denied = await server.get('/doc/d1', 'ana', 'DELETE');
    assert.deepEqual([denied.status, denied.body.error.code], [403, 'forbidden']);
    const uncovered = await server.get('/open', 'ana');
    assert.deepEqual([uncovered.status, uncovered.body.error.code], [403, 'forbidden'], 'a route with no rule is refused');
    assert.equal((await server.get('/nowhere', 'ana')).status, 403);
  } finally {
    await server.close();
  }
});

await test('express: denyStatus applies to the uncovered route', async () => {
  const server = await listen(expressApp({ local: await localMode(), denyStatus: 404 }));
  try {
    assert.equal((await server.get('/open', 'ana')).status, 404);
  } finally {
    await server.close();
  }
});

await test('express: an unreadable request is refused with errorStatus and reaches onError', async () => {
  const seen: unknown[] = [];
  const mw = authorizeRoutes({ subject: subjectOf, local: await localMode(), routes: table, onError: (e) => seen.push(e) });
  const sent: unknown[] = [];
  const res = { status(s: number) { sent.push(s); return this; }, json() {} };
  let nexted = 0;
  await mw({ method: undefined, url: '/health' } as never, res, () => (nexted += 1));
  assert.deepEqual(sent, [500]);
  assert.equal(seen.length, 1);
  assert.equal(nexted, 0);
});

// ---- Nest ----

class Controller {
  doc() {}
  strict() {}
}
Can('project.edit')(Controller.prototype, 'strict', Object.getOwnPropertyDescriptor(Controller.prototype, 'strict')!);
const ctx = (handler: Function, method: string, url: string, user?: string, type?: string) => ({
  getHandler: () => handler,
  getClass: () => Controller,
  getType: () => type ?? 'http',
  switchToHttp: () => ({ getRequest: () => ({ method, originalUrl: url, headers: user ? { 'x-user': user } : {} }) }),
});
const status = (e: unknown) => (e as { getStatus(): number }).getStatus();

await test('nestjs: the table decides, and @Can only narrows', async () => {
  const guard = new StrigRouteGuard({ subject: subjectOf, resource: () => docOf(0, { id: 'd1' }), local: await localMode(), routes: table });
  assert.equal(await guard.canActivate(ctx(Controller.prototype.doc, 'GET', '/doc/d1', 'ana')), true, 'no @Can: the table is enough');
  assert.equal(await guard.canActivate(ctx(Controller.prototype.doc, 'GET', '/health')), true);
  await assert.rejects(guard.canActivate(ctx(Controller.prototype.doc, 'GET', '/open', 'ana')), (e) => status(e) === 403);
  await assert.rejects(guard.canActivate(ctx(Controller.prototype.doc, 'GET', '/doc/d1')), (e) => status(e) === 401);
  // The table allows GET /doc/:id (document.view) but @Can('project.edit') on the handler is not granted: it closes.
  await assert.rejects(guard.canActivate(ctx(Controller.prototype.strict, 'GET', '/doc/d1', 'ana')), (e) => status(e) === 403);
  // @Can on a public rule still applies (it adds a requirement); here the caller is anonymous.
  await assert.rejects(guard.canActivate(ctx(Controller.prototype.strict, 'GET', '/health')), (e) => status(e) === 401);
});

await test('nestjs: a non-HTTP context is refused with errorStatus and reaches onError', async () => {
  const seen: unknown[] = [];
  const guard = new StrigRouteGuard({ subject: subjectOf, local: await localMode(), routes: table, errorStatus: 502, onError: (e) => seen.push(e) });
  await assert.rejects(guard.canActivate(ctx(Controller.prototype.doc, 'GET', '/health', undefined, 'rpc')), (e) => status(e) === 502);
  assert.equal(seen.length, 1);
});

// ---- Fastify ----

await test('fastify: onRequest hook decides every request', async () => {
  const app = Fastify();
  const routes = collectFastifyRoutes(app);
  app.addHook('onRequest', fastifyAuthorize({ subject: subjectOf, local: await localMode(), routes: table }));
  app.get('/health', async () => ({ ok: true }));
  app.get('/doc/:id', async () => ({ ok: true }));
  app.get('/open', async () => ({ ok: true }));
  await app.ready();
  try {
    const code = async (url: string, user?: string) => (await app.inject({ method: 'GET', url, headers: user ? { 'x-user': user } : {} })).statusCode;
    assert.equal(await code('/health'), 200);
    assert.equal(await code('/doc/d1', 'ana'), 200);
    assert.equal(await code('/doc/d1'), 401);
    assert.equal(await code('/open', 'ana'), 403);
    assert.equal(await code('/nowhere', 'ana'), 403);
    const audit = auditRoutes(routes, table);
    assert.deepEqual([...new Set(audit.uncovered.map((r) => r.path))], ['/open'], 'GET and the HEAD fastify adds');
  } finally {
    await app.close();
  }
});

// ---- Audit ----

await test('audit: lists routes with no rule and rules with no route (express, nested router, nest adapter)', () => {
  const app = express();
  const api = express.Router();
  api.get('/doc/:id', () => {});
  api.get('/extra', () => {});
  app.get('/health', () => {});
  app.use('/api', api);
  const routes = expressRoutes(app);
  assert.deepEqual(routes.map((r) => `${r.method} ${r.path}`).sort(), ['GET /api/doc/:id', 'GET /api/extra', 'GET /health']);
  const rules: RouteRule[] = [
    { method: 'GET', path: '/health', public: true },
    { method: 'GET', path: '/api/doc/:id', permission: 'document.view' },
    { method: 'GET', path: '/gone', public: true },
    { method: 'GET', path: '/health', permission: 'a.b' },
  ];
  const audit = auditRoutes(routes, rules);
  assert.deepEqual(audit.uncovered.map((r) => r.path), ['/api/extra']);
  assert.deepEqual(audit.unusedRules.map((r) => r.path), ['/gone', '/health'], 'a shadowed rule is unused too');
  assert.throws(() => assertRoutesCovered(routes, rules), /routes with no rule:\n {2}GET \/api\/extra[\s\S]*rules with no route:\n {2}GET \/gone/);
  assert.doesNotThrow(() => assertRoutesCovered(routes, [...rules.slice(0, 2), { method: 'GET', path: '/api/extra', public: true }]));
  assert.deepEqual(nestRoutes({ getHttpAdapter: () => ({ getInstance: () => app }) }), routes);
});

await test('audit: a route for every method and a wildcard route need a matching rule', () => {
  const app = express();
  app.all('/any', () => {});
  app.get('/f/:name', () => {});
  const routes = expressRoutes(app);
  assert.deepEqual(routes.map((r) => r.method).sort(), ['*', 'GET']);
  const audit = auditRoutes(routes, [{ method: 'GET', path: '/any', public: true }, { method: 'GET', path: '/f/*', public: true }]);
  assert.deepEqual(audit.uncovered.map((r) => r.path), ['/any'], 'a GET rule does not cover app.all');
  assert.deepEqual(audit.unusedRules.map((r) => r.path), ['/any'], 'and that GET rule decides no route');
  assert.throws(() => expressRoutes({}), TypeError);
  assert.throws(() => nestRoutes({ getHttpAdapter: () => ({ getInstance: () => ({ addHook() {} }) }) }), /collectFastifyRoutes/);
});

// ---- The table matches the way the framework routes ----
// A broad public rule after the protected one is what a bypass needs: the request must not slip past `/admin/:id`.
const guarded: RouteRule[] = [
  { method: 'GET', path: '/admin/:id', permission: 'project.edit', resource: docOf },
  { method: 'GET', path: '/*', public: true },
];

await test('matching: escapes are decoded per segment, %2F stays inside its segment, case is an option', () => {
  const t = compileRoutes(guarded);
  assert.equal(t.match('GET', '/%61dmin/1')?.rule.permission, 'project.edit');
  assert.equal(t.match('GET', '/admin%2F1')?.rule.public, true, 'one segment "admin/1" is not /admin/:id');
  assert.equal(t.match('GET', '/%E0%A4%A/1'), undefined, 'a malformed escape matches nothing');
  assert.equal(compileRoutes(table).match('GET', '/doc/a%2Fb')?.params.id, 'a/b');
  assert.equal(t.match('GET', '/ADMIN/1')?.rule.public, true, 'case sensitive by default');
  assert.equal(t.match('GET', '/ADMIN/1', false)?.rule.permission, 'project.edit');
});

await test('express: /ADMIN/1 and /%61dmin/1 hit the protected rule, not the public one after it', async () => {
  const app = express();
  app.use(authorizeRoutes({ subject: subjectOf, local: await localMode(), routes: guarded }));
  app.get('/admin/:id', (_req, res) => res.json({ admin: true }));
  const server = await listen(app);
  try {
    for (const path of ['/admin/1', '/ADMIN/1', '/%61dmin/1', '/Admin/1']) assert.equal((await server.get(path)).status, 401, path);
    assert.equal((await server.get('/ADMIN/1', 'ana')).status, 403, 'a member is denied project.edit');
  } finally {
    await server.close();
  }
});

await test('fastify: /%61dmin/1 hits the protected rule; case follows the Fastify option', async () => {
  const run = async (caseSensitive: boolean | undefined, fastifyOption: boolean) => {
    const app = Fastify({ caseSensitive: fastifyOption });
    app.addHook('onRequest', fastifyAuthorize({ subject: subjectOf, local: await localMode(), routes: guarded, caseSensitive }));
    app.get('/admin/:id', async () => ({ admin: true }));
    await app.ready();
    const code = async (url: string) => (await app.inject({ method: 'GET', url })).statusCode;
    const out = { plain: await code('/admin/1'), escaped: await code('/%61dmin/1'), upper: await code('/ADMIN/1') };
    await app.close();
    return out;
  };
  assert.deepEqual(await run(undefined, true), { plain: 401, escaped: 401, upper: 404 }, 'Fastify default: /ADMIN/1 has no route');
  assert.deepEqual(await run(false, false), { plain: 401, escaped: 401, upper: 401 }, 'Fastify caseSensitive: false');
});

await test('nestjs: the guard follows the platform and escapes are decoded', async () => {
  const guard = new StrigRouteGuard({ subject: subjectOf, local: await localMode(), routes: guarded });
  const at = (url: string, raw?: object) => ({
    getHandler: () => Controller.prototype.doc,
    getClass: () => Controller,
    getType: () => 'http',
    switchToHttp: () => ({ getRequest: () => ({ method: 'GET', originalUrl: url, headers: {}, raw }) }),
  });
  for (const url of ['/admin/1', '/ADMIN/1', '/%61dmin/1']) await assert.rejects(guard.canActivate(at(url)), (e) => status(e) === 401, `express platform ${url}`);
  await assert.rejects(guard.canActivate(at('/%61dmin/1', {})), (e) => status(e) === 401, 'fastify platform, escaped');
  assert.equal(await guard.canActivate(at('/ADMIN/1', {})), true, 'fastify platform: another path, public');
  const forced = new StrigRouteGuard({ subject: subjectOf, local: await localMode(), routes: guarded, caseSensitive: false });
  await assert.rejects(forced.canActivate(at('/ADMIN/1', {})), (e) => status(e) === 401);
});
