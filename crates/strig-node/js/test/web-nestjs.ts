// The guard is driven with a hand-made execution context: the decorator and the guard are what is under test, not the HTTP adapter.
import 'reflect-metadata';
import assert from 'node:assert/strict';
import type { Subject } from '../dist/index.js';
import { Can, StrigGuard } from '../dist/nestjs.js';
import type { AuthorizerOptions } from '../dist/nestjs.js';
import { harness, localMode, resourceOf, runSuite, subjectOf } from './web-suite.js';

type WebReq = { headers?: Record<string, string | string[] | undefined>; params: { id: string } };
type HttpError = { getStatus(): number; getResponse(): unknown };
const asyncSubject = (async () => ({ kind: 'user', id: 'a' })) as unknown as () => Subject;

class Controller {
  doc() {}
  bare() {}
}
Can('document.view')(Controller.prototype, 'doc', Object.getOwnPropertyDescriptor(Controller.prototype, 'doc')!);
Can('project.edit', (req: WebReq) => resourceOf(req))(Controller.prototype, 'bare', Object.getOwnPropertyDescriptor(Controller.prototype, 'bare')!);

const contextOf = (handler: Function, request: WebReq) => ({ getHandler: () => handler, getClass: () => Controller, switchToHttp: () => ({ getRequest: () => request }) });
const request = (user: string | undefined, id: string): WebReq => ({ headers: user ? { 'x-user': user } : {}, params: { id } });

await runSuite('nestjs', async (options) => {
  // `@Can('document.view')` is the permission of `doc`; the suite's own permission is applied by re-decorating.
  const handler = function handler() {};
  const { permission, ...rest } = options;
  Can(permission)(Controller.prototype, 'x', { value: handler });
  const guard = new StrigGuard(rest as AuthorizerOptions);
  return {
    async call(user, id) {
      try {
        const ok = await guard.canActivate(contextOf(handler, request(user, id)));
        return { status: ok ? 200 : 500, body: {}, handlerRan: ok };
      } catch (error) {
        const http = error as HttpError;
        return { status: http.getStatus(), body: http.getResponse(), handlerRan: false };
      }
    },
    close: async () => {},
  };
});

const { test } = harness('nestjs');
await test('@Can on a method: the declared permission and the resolver decide', async () => {
  const local = await localMode();
  const guard = new StrigGuard({ subject: subjectOf, resource: resourceOf, local });
  assert.equal(await guard.canActivate(contextOf(Controller.prototype.doc, request('ana', 'd1'))), true);
  await assert.rejects(guard.canActivate(contextOf(Controller.prototype.bare, request('ana', 'd1'))), (e: HttpError) => e.getStatus() === 403);
});

await test('a guarded handler with no @Can is refused, not opened', async () => {
  const guard = new StrigGuard({ subject: subjectOf, resource: resourceOf, local: await localMode() });
  await assert.rejects(guard.canActivate(contextOf(function undeclared() {}, request('ana', 'd1'))), (e: HttpError) => e.getStatus() === 500);
});

await test('@Can rejects an empty permission', () => {
  assert.throws(() => Can(''), TypeError);
});

await test('@Can at the class level applies to every handler', async () => {
  class Whole { a() {} }
  Can('document.view')(Whole);
  const ctx = (request: WebReq) => ({ getHandler: () => Whole.prototype.a, getClass: () => Whole, switchToHttp: () => ({ getRequest: () => request }) });
  const guard = new StrigGuard({ subject: subjectOf, resource: resourceOf, local: await localMode() });
  assert.equal(await guard.canActivate(ctx(request('ana', 'd1'))), true);
});

await test('a non-HTTP context is refused with 500 and reaches onError', async () => {
  const seen: string[] = [];
  const guard = new StrigGuard({ subject: subjectOf, resource: resourceOf, local: await localMode(), errorStatus: 502, onError: (e) => { seen.push((e as Error).message); } });
  const rpc = { ...contextOf(Controller.prototype.doc, request('ana', 'd1')), getType: () => 'rpc' };
  await assert.rejects(guard.canActivate(rpc), (e: HttpError) => e.getStatus() === 502);
  assert.equal(seen.length, 1);
  await assert.rejects(guard.canActivate(contextOf(function undeclared() {}, request('ana', 'd1'))), (e: HttpError) => e.getStatus() === 502);
  assert.equal(seen.length, 2, 'the missing @Can is reported too');
});

await test('a guard whose onError throws still refuses', async () => {
  const guard = new StrigGuard({ subject: subjectOf, resource: resourceOf, local: await localMode(), onError: (e) => { throw e; } });
  await assert.rejects(guard.canActivate(contextOf(function undeclared() {}, request('ana', 'd1'))), (e: HttpError) => e.getStatus() === 500);
});

await test('an empty @Can permission and an async extractor are refused', async () => {
  const guard = new StrigGuard({ subject: asyncSubject, resource: resourceOf, local: await localMode() });
  await assert.rejects(guard.canActivate(contextOf(Controller.prototype.doc, request('ana', 'd1'))), (e: HttpError) => e.getStatus() === 500);
});
