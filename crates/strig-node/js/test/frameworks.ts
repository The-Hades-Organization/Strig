// React and Angular bindings, driven by a real PermissionClient over a controllable SSE stream (no network, no browser).
// The decision engine is a stub: what is under test is the bridge (allow, deny, updates, disconnect, SSR), not the engine.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JSDOM } from 'jsdom';
import { PermissionClient } from '../dist/client.js';
import { encodeSse, scopeToString } from '../dist/protocol.js';
import type { Resource, ServerMessage } from '../dist/protocol.js';
import { harness } from './web-suite.js';

const { test } = harness('frameworks');

const project: Resource = { path: [{ kind: 'project', id: 'p1' }, { kind: 'org', id: 'o1' }] };
const other: Resource = { path: [{ kind: 'project', id: 'p2' }, { kind: 'org', id: 'o2' }] };
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(check: () => unknown, ms = 2000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (check()) return;
    await sleep(5);
  }
  throw new Error('condition not reached in time');
}

class StubContext {
  permissions: string[] = [];
  loadCapabilities(set: { grants: Array<{ permission: string }> }): void {
    this.permissions = set.grants.map((g) => g.permission);
  }
}
const stubEngine = {
  decide: (context: StubContext, request: { permission: string }) => ({
    effect: context.permissions.includes(request.permission) ? 'allow' : 'deny',
    reason: { kind: 'no_applicable_grant' },
    warnings: [],
  }),
};

/** A client whose SSE stream the test controls. `push` sends a server message, `drop` ends the stream. */
function fakeClient() {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let opened = 0;
  const encoder = new TextEncoder();
  const fakeFetch = (async (_url: unknown, init?: RequestInit) => {
    opened += 1;
    const body = new ReadableStream<Uint8Array>({
      start: (c) => {
        controller = c;
        init?.signal?.addEventListener('abort', () => c.error(Object.assign(new Error('aborted'), { name: 'AbortError' })));
      },
    });
    return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
  }) as unknown as typeof fetch;
  const client = new PermissionClient<'project.view' | 'project.edit'>({
    url: 'http://localhost/stream',
    scopes: [project],
    strig: { Context: StubContext } as never,
    engine: stubEngine as never,
    fetch: fakeFetch,
    reconnectMinMs: 5,
    reconnectMaxMs: 20,
  });
  const push = (message: ServerMessage) => controller.enqueue(encoder.encode(encodeSse(message)));
  return {
    client,
    push,
    drop: () => controller.close(),
    get opened() {
      return opened;
    },
    hello: () => push({ type: 'hello', origin: 'test' }),
    capabilities: (...permissions: string[]) =>
      push({ type: 'capabilities', scope: project, set: { subject: { kind: 'user', id: 'ana' }, grants: permissions.map((permission) => ({ permission })) } }),
  };
}

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost/' });
const saved = new Map<string, PropertyDescriptor | undefined>();
const exposed: Record<string, unknown> = {
  window: dom.window,
  document: dom.window.document,
  navigator: dom.window.navigator,
  HTMLElement: dom.window.HTMLElement,
  Element: dom.window.Element,
  Node: dom.window.Node,
  MutationObserver: dom.window.MutationObserver,
  getComputedStyle: dom.window.getComputedStyle.bind(dom.window),
  requestAnimationFrame: (cb: (t: number) => void) => setTimeout(() => cb(Date.now()), 0),
  cancelAnimationFrame: (id: number) => clearTimeout(id),
  IS_REACT_ACT_ENVIRONMENT: true,
};
for (const [key, value] of Object.entries(exposed)) {
  saved.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
  Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
}

try {
  const React = await import('react');
  const { render, cleanup, act } = await import('@testing-library/react');
  const { renderToString } = await import('react-dom/server');
  const { StrigProvider, useCan, Can, useStrigStatus } = await import('../dist/react.js');
  const h = React.createElement;

  const mount = (client: PermissionClient<any>, ui: React.ReactNode, connect = true) =>
    render(h(StrigProvider, { client, connect }, ui));
  const Status = () => {
    const s = useStrigStatus();
    return h('span', { 'data-testid': 'status' }, `${s.connected}/${s.resyncing}/${s.error?.message ?? '-'}`);
  };
  const Probe = ({ permission = 'project.view', resource = project }: { permission?: string; resource?: Resource }) =>
    h('span', { 'data-testid': 'can' }, String(useCan(permission as never, resource)));

  await test('react: denies before any decision, allows when capabilities arrive, updates on a new set', async () => {
    const fake = fakeClient();
    const view = mount(fake.client, h(Probe));
    assert.equal(view.getByTestId('can').textContent, 'false');
    await until(() => fake.opened === 1);
    fake.hello();
    await act(async () => fake.capabilities('project.view'));
    await until(() => view.getByTestId('can').textContent === 'true');
    await act(async () => fake.capabilities('project.edit'));
    await until(() => view.getByTestId('can').textContent === 'false');
    view.unmount();
    cleanup();
    await sleep(20);
  });

  await test('react: <Can> shows children on allow and the fallback on deny, and a scope outside the grants denies', async () => {
    const fake = fakeClient();
    const view = mount(
      fake.client,
      h(
        'div',
        null,
        h(Can, { permission: 'project.view' as never, resource: project, fallback: h('i', null, 'denied-p1') }, h('b', null, 'allowed-p1')),
        h(Can, { permission: 'project.view' as never, resource: other, fallback: h('i', null, 'denied-p2') }, h('b', null, 'allowed-p2')),
      ),
    );
    assert.ok(view.queryByText('denied-p1'), 'fallback while there is no decision');
    await until(() => fake.opened === 1);
    fake.hello();
    await act(async () => fake.capabilities('project.view'));
    await until(() => view.queryByText('allowed-p1'));
    assert.ok(view.queryByText('denied-p2'));
    view.unmount();
    cleanup();
    await sleep(20);
  });

  await test('react: disconnect denies, reconnect restores, status follows', async () => {
    const fake = fakeClient();
    const view = mount(fake.client, h('div', null, h(Probe), h(Status)));
    await until(() => fake.opened === 1);
    fake.hello();
    await act(async () => fake.capabilities('project.view'));
    await until(() => view.getByTestId('can').textContent === 'true');
    assert.equal(view.getByTestId('status').textContent, 'true/false/-');
    await act(async () => fake.drop());
    await until(() => view.getByTestId('can').textContent === 'false');
    assert.equal(view.getByTestId('status').textContent?.startsWith('false'), true);
    await until(() => fake.opened === 2);
    fake.hello();
    await act(async () => fake.capabilities('project.view'));
    await until(() => view.getByTestId('can').textContent === 'true');
    view.unmount();
    cleanup();
    await sleep(20);
  });

  await test('react: a resync denies until the new capabilities, and a server error shows in the status', async () => {
    const fake = fakeClient();
    const view = mount(fake.client, h('div', null, h(Probe), h(Status)));
    await until(() => fake.opened === 1);
    fake.hello();
    await act(async () => fake.capabilities('project.view'));
    await until(() => view.getByTestId('can').textContent === 'true');
    await act(async () => fake.push({ type: 'resync' }));
    await until(() => view.getByTestId('status').textContent === 'false/true/-');
    assert.equal(view.getByTestId('can').textContent, 'false');
    await act(async () => fake.push({ type: 'error', message: 'boom' }));
    await until(() => view.getByTestId('status').textContent === 'false/true/boom');
    await act(async () => fake.capabilities('project.view'));
    await until(() => view.getByTestId('status').textContent === 'true/false/-');
    view.unmount();
    cleanup();
    await sleep(20);
  });

  await test('react: without a provider everything denies', () => {
    const view = render(h('div', null, h(Probe), h(Status)));
    assert.equal(view.getByTestId('can').textContent, 'false');
    assert.equal(view.getByTestId('status').textContent, 'false/false/-');
    view.unmount();
    cleanup();
  });

  await test('react: the server render denies and never opens the stream', () => {
    const fake = fakeClient();
    const html = renderToString(h(StrigProvider, { client: fake.client as never }, h(Probe), h(Can, { permission: 'project.view' as never, resource: project, fallback: 'nope' }, 'secret')));
    assert.ok(html.includes('false'));
    assert.ok(html.includes('nope'));
    assert.ok(!html.includes('secret'));
    assert.equal(fake.opened, 0);
  });

  await test('react: unmounting closes the stream; connect=false never opens it', async () => {
    const fake = fakeClient();
    const view = mount(fake.client, h(Probe));
    await until(() => fake.opened === 1);
    let closed = false;
    fake.client.on('close', () => void (closed = true));
    view.unmount();
    await until(() => closed);
    const idle = fakeClient();
    const quiet = mount(idle.client, h(Probe), false);
    await sleep(30);
    assert.equal(idle.opened, 0);
    quiet.unmount();
    cleanup();
  });

  await import('@angular/compiler');
  const core = await import('@angular/core');
  const { TestBed, getTestBed } = await import('@angular/core/testing');
  const { BrowserDynamicTestingModule, platformBrowserDynamicTesting } = await import('@angular/platform-browser-dynamic/testing');
  const { provideStrig, StrigService, StrigCanDirective, strigCanActivate } = await import('../dist/angular.js');
  getTestBed().initTestEnvironment(BrowserDynamicTestingModule, platformBrowserDynamicTesting());

  const hostOf = (template: string, props: Record<string, unknown>) => {
    class Host {}
    Object.assign(Host.prototype, props);
    core.Component({ selector: 'host', standalone: true, imports: [StrigCanDirective], template })(Host);
    return Host;
  };
  const setup = (fake: ReturnType<typeof fakeClient>, extra: unknown[] = []) =>
    TestBed.configureTestingModule({ providers: [core.provideZonelessChangeDetection(), provideStrig(fake.client), ...extra] });
  const settle = async (fixture: { detectChanges(): void; whenStable(): Promise<unknown> }) => {
    await fixture.whenStable();
    fixture.detectChanges();
    await fixture.whenStable();
  };

  await test('angular: can() is a signal that denies, then allows, then follows a new set', async () => {
    const fake = fakeClient();
    setup(fake);
    const service = TestBed.inject(StrigService);
    const view = service.can('project.view', project);
    assert.equal(view(), false);
    await until(() => fake.opened === 1);
    fake.hello();
    fake.capabilities('project.view');
    await until(() => view());
    assert.equal(service.can('project.edit', project)(), false);
    fake.capabilities('project.edit');
    await until(() => !view());
    assert.equal(service.status().connected, true);
    TestBed.resetTestingModule();
    await sleep(20);
  });

  await test('angular: *strigCan renders the template on allow and the else template otherwise', async () => {
    const fake = fakeClient();
    setup(fake);
    const Host = hostOf(
      `<p *strigCan="'project.view'; resource: r1; else denied" id="yes">yes</p>
       <p *strigCan="'project.view'; resource: r2; else denied" id="other">other</p>
       <ng-template #denied><i class="no">no</i></ng-template>`,
      { r1: project, r2: other },
    );
    const fixture = TestBed.createComponent(Host);
    await settle(fixture);
    const el = fixture.nativeElement as HTMLElement;
    assert.equal(el.querySelectorAll('.no').length, 2, 'else shows while there is no decision');
    assert.equal(el.querySelector('#yes'), null);
    await until(() => fake.opened === 1);
    fake.hello();
    fake.capabilities('project.view');
    await until(() => (fake.client.capabilities(project) ? true : false));
    await sleep(10);
    await settle(fixture);
    assert.ok(el.querySelector('#yes'));
    assert.equal(el.querySelector('#other'), null);
    assert.equal(el.querySelectorAll('.no').length, 1);
    fake.drop();
    await until(() => !TestBed.inject(StrigService).status().connected);
    await settle(fixture);
    assert.equal(el.querySelector('#yes'), null, 'a dropped connection denies');
    fixture.destroy();
    TestBed.resetTestingModule();
    await sleep(20);
  });

  await test('angular: *strigCan without an else template renders nothing on deny', async () => {
    const fake = fakeClient();
    setup(fake);
    const Host = hostOf(`<p *strigCan="'project.view'; resource: r" id="yes">yes</p>`, { r: project });
    const fixture = TestBed.createComponent(Host);
    await settle(fixture);
    assert.equal((fixture.nativeElement as HTMLElement).querySelector('#yes'), null);
    fixture.destroy();
    TestBed.resetTestingModule();
    await sleep(20);
  });

  await test('angular: the route guard waits for capabilities, allows, denies, and denies on timeout', async () => {
    const fake = fakeClient();
    setup(fake);
    TestBed.inject(StrigService);
    const run = (guard: ReturnType<typeof strigCanActivate>) => TestBed.runInInjectionContext(() => guard({}, {}));
    const pending = run(strigCanActivate('project.view', () => project, { waitMs: 1000 }));
    await until(() => fake.opened === 1);
    fake.hello();
    fake.capabilities('project.view');
    assert.equal(await pending, true);
    assert.equal(await run(strigCanActivate('project.edit', project)), false);
    assert.equal(await run(strigCanActivate('project.view', other)), false);
    assert.equal(await run(strigCanActivate('project.edit', project, { onDeny: () => 'redirect' })), 'redirect');
    TestBed.resetTestingModule();
    await sleep(20);
    const silent = fakeClient();
    setup(silent);
    TestBed.inject(StrigService);
    assert.equal(await run(strigCanActivate('project.view', project, { waitMs: 30 })), false, 'no decision in time denies');
    TestBed.resetTestingModule();
    await sleep(20);
  });

  await test('angular: the server platform denies and never opens the stream', async () => {
    const fake = fakeClient();
    setup(fake, [{ provide: core.PLATFORM_ID, useValue: 'server' }]);
    const service = TestBed.inject(StrigService);
    await sleep(30);
    assert.equal(fake.opened, 0);
    assert.equal(service.can('project.view', project)(), false);
    TestBed.resetTestingModule();
  });

  await test('scope sanity: the stub scopes match the way the client keys them', () => {
    assert.equal(scopeToString(project), 'project:p1/org:o1');
  });
} finally {
  for (const [key, descriptor] of saved) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else delete (globalThis as Record<string, unknown>)[key];
  }
}

// A missing peer: the entry is loaded from a folder with no node_modules, so `react` and `@angular/core` cannot resolve.
for (const [entry, peer] of [['react.js', 'react'], ['angular.js', '@angular/core']] as const) {
  await test(`${entry}: a missing peer fails at resolution naming "${peer}"`, () => {
    const dir = mkdtempSync(join(tmpdir(), 'strig-peer-'));
    try {
      mkdirSync(join(dir, 'dist'));
      mkdirSync(join(dir, 'package'));
      const src = new URL('../dist/', import.meta.url);
      for (const file of readdirSync(src)) if (file.endsWith('.js')) copyFileSync(new URL(file, src), join(dir, 'package', file));
      writeModulePackage(join(dir, 'package'));
      assert.throws(
        () => execFileSync('node', ['--input-type=module', '-e', `await import(${JSON.stringify(join(dir, 'package', entry))})`], { stdio: 'pipe' }),
        (error: Error & { stderr?: Buffer }) => String(error.stderr).includes(`'${peer}'`) && /Cannot find (package|module)/.test(String(error.stderr)),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

function writeModulePackage(dir: string): void {
  execFileSync(process.execPath, ['-e', `require('fs').writeFileSync(${JSON.stringify(join(dir, 'package.json'))}, '{"type":"module"}')`]);
}
