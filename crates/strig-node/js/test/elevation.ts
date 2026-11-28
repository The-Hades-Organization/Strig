// Temporary elevation and break-glass: request, approval, maximum duration, expiry, revocation, review and the JSON store.
// Runs on both backends (N-API and wasm); `run.js` imports this file.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Elevations, MemoryPendingStore } from '../dist/approvals.js';
import type { ApplyInput, ElevationRequest, ElevationRule, EngineHooks, Grant, InvariantSpec, Subject } from '../dist/index.js';
import { load } from '../dist/node.js';
import { openJsonStore } from '../dist/store.js';

let failures = 0;
async function test(name: string, fn: (dir: string) => unknown) {
  const dir = await mkdtemp(join(tmpdir(), 'strig-elevation-'));
  try {
    await fn(dir);
    console.log(`ok - ${name}`);
  } catch (error) {
    failures += 1;
    process.exitCode = 1;
    console.log(`not ok - ${name}\n  ${error instanceof Error ? error.stack : error}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const SPEC = {
  catalog: {
    targetKinds: ['project'],
    broadTargets: ['org'],
    permissions: [
      { key: 'project.view', targets: ['project'] },
      { key: 'project.edit', targets: ['project'] },
      { key: 'grants.manage', targets: ['project'] },
    ],
  },
};
const HOUR = 3_600_000;
const T0 = 1_700_000_000_000;
const project = { path: [{ kind: 'project', id: 'p1' }] };
const admin = (id: string): Subject => ({ kind: 'user', id, roles: [{ role: 'admin' }] });
const ana: Subject = { kind: 'user', id: 'ana' };
const adminGrant: Grant = { id: 'adm', subject: { kind: 'role', id: 'admin' }, permission: 'grants.manage', target: { kind: 'project' }, effect: 'allow' };
const invariants: InvariantSpec[] = [{ kind: 'catalog_conformance' }];
const edit = { kind: 'permission', permission: 'project.edit', target: { kind: 'project', id: 'p1' } } as const;
const rule = (extra: Partial<ElevationRule> = {}): ElevationRule => ({
  key: { permission: 'project.edit' },
  maxDurationMs: 4 * HOUR,
  approverPermission: 'grants.manage',
  approverResource: project,
  requireJustification: true,
  ...extra,
});
const ask = (id: string, durationMs: number, extra: Partial<ElevationRequest> = {}): ElevationRequest => ({
  id,
  actor: ana,
  target: edit,
  durationMs,
  justification: 'incident 42',
  ...extra,
});

for (const backend of ['native', 'wasm'] as const) {
  const setup = async (options: { rule?: ElevationRule; level?: 'standard' | 'forensic'; hooks?: EngineHooks } = {}) => {
    const { Engine } = await load({ backend });
    const store = new MemoryPendingStore();
    const audit: ApplyInput['audit'] = { level: options.level ?? 'forensic' };
    const flow = new Elevations(new Engine(SPEC, options.hooks), store, { elevation: [options.rule ?? rule()], invariants, audit });
    return { flow, store };
  };
  const current = [adminGrant];

  await test(`${backend}: o pedido espera, a aprovação abre a janela a partir dela e o prazo a fecha`, async () => {
    const { flow } = await setup();
    const asked = await flow.request(ask('e1', 2 * HOUR), current, { now: T0 });
    assert.ok(asked.ok && asked.applied === false);
    assert.deepEqual(await flow.active(T0), []);

    const done = await flow.approve('e1', admin('bia'), current, { now: T0 + 500 });
    assert.ok(done.ok);
    const grant = done.grants?.find((g) => g.id === 'elevation:e1');
    assert.equal(grant?.validFrom, T0 + 500);
    assert.equal(grant?.validUntil, T0 + 500 + 2 * HOUR);
    assert.equal((await flow.active(T0 + 500)).length, 1);
    assert.equal((await flow.active(T0 + 500 + 2 * HOUR - 1)).length, 1);
    assert.equal((await flow.active(T0 + 500 + 2 * HOUR)).length, 0);
  });

  await test(`${backend}: prazo além do máximo, justificativa ausente e alvo fora da política são recusados`, async () => {
    const { flow, store } = await setup();
    const over = await flow.request(ask('e1', 4 * HOUR + 1), current, { now: T0 });
    assert.ok(!over.ok && over.code === 'REFUSED');
    assert.deepEqual(over.violations.map((v) => v.invariant), ['elevation_duration']);
    const bare = await flow.request(ask('e2', HOUR, { justification: undefined }), current, { now: T0 });
    assert.ok(!bare.ok && bare.code === 'REFUSED');
    assert.deepEqual(bare.violations.map((v) => v.invariant), ['elevation_justification']);
    const other = await flow.request(ask('e3', HOUR, { target: { kind: 'role', role: 'admin' } }), current, { now: T0 });
    assert.ok(!other.ok && other.code === 'REFUSED');
    assert.deepEqual(await store.list(), []);
  });

  await test(`${backend}: o autor não aprova o próprio pedido e quem não tem a permissão também não`, async () => {
    const { flow, store } = await setup();
    const author = admin('ana');
    await flow.request(ask('e1', HOUR, { actor: author }), current, { now: T0 });
    const self = await flow.approve('e1', author, current, { now: T0 + 1 });
    assert.ok(!self.ok && self.code === 'REFUSED');
    const stranger = await flow.approve('e1', { kind: 'user', id: 'caio' }, current, { now: T0 + 1 });
    assert.ok(!stranger.ok && stranger.code === 'REFUSED');
    assert.equal((await store.get('e1'))?.status.state, 'pending');
  });

  await test(`${backend}: revogação pelo ator ou por um aprovador, e só uma vez`, async () => {
    const { flow } = await setup();
    let grants = current;
    await flow.request(ask('e1', 2 * HOUR), grants, { now: T0 });
    const approved = await flow.approve('e1', admin('bia'), grants, { now: T0 + 1 });
    assert.ok(approved.ok && approved.grants);
    grants = approved.grants;

    const stranger = await flow.revoke('e1', { kind: 'user', id: 'caio' }, grants, { now: T0 + 5 });
    assert.ok(!stranger.ok && stranger.code === 'REFUSED');
    assert.equal((await flow.active(T0 + 6)).length, 1);

    const revoked = await flow.revoke('e1', ana, grants, { now: T0 + 10, reason: 'done' });
    assert.ok(revoked.ok);
    assert.equal(revoked.grants?.some((g) => g.id === 'elevation:e1'), false);
    assert.equal(revoked.request.elevation?.revoked?.at, T0 + 10);
    assert.equal((await flow.active(T0 + 11)).length, 0);
    const again = await flow.revoke('e1', admin('bia'), revoked.grants ?? [], { now: T0 + 20 });
    assert.ok(!again.ok && again.code === 'REFUSED');
  });

  await test(`${backend}: break-glass vale na hora, fica marcado, grava forensic e a revisão a fecha outro ator`, async () => {
    const records: Array<Record<string, unknown>> = [];
    const { flow } = await setup({ rule: rule({ breakGlass: { maxDurationMs: HOUR } }), hooks: { auditSink: (record) => void records.push(record) } });
    const result = await flow.request(ask('e1', HOUR, { breakGlass: true }), current, { now: T0 });
    assert.ok(result.ok && result.applied === true);
    assert.equal(result.grants?.find((g) => g.id === 'elevation:e1')?.validUntil, T0 + HOUR);
    assert.equal(result.request.elevation?.breakGlass, true);
    assert.equal(result.request.elevation?.review?.state, 'pending');
    assert.ok(records.length > 0);
    assert.equal(records.every((r) => r.level === 'forensic'), true);
    assert.equal((await flow.pendingReviews()).length, 1);

    const own = await flow.closeReview('e1', ana, 'ok', current, { now: T0 + 5 });
    assert.ok(!own.ok && own.code === 'REFUSED');
    const closed = await flow.closeReview('e1', admin('bia'), 'legitimate use', current, { now: T0 + 60 });
    assert.ok(closed.ok);
    assert.equal(closed.request.elevation?.review?.state, 'closed');
    assert.equal((await flow.pendingReviews()).length, 0);
  });

  await test(`${backend}: break-glass proibido pela política, longo demais ou sem justificativa é recusado`, async () => {
    const forbidden = await setup();
    const no = await forbidden.flow.request(ask('e1', HOUR, { breakGlass: true }), current, { now: T0 });
    assert.ok(!no.ok && no.code === 'REFUSED');
    assert.deepEqual(no.violations.map((v) => v.invariant), ['break_glass']);

    const allowed = await setup({ rule: rule({ breakGlass: { maxDurationMs: HOUR } }) });
    const long = await allowed.flow.request(ask('e2', HOUR + 1, { breakGlass: true }), current, { now: T0 });
    assert.ok(!long.ok && long.code === 'REFUSED');
    const mute = await allowed.flow.request(ask('e3', HOUR, { breakGlass: true, justification: undefined }), current, { now: T0 });
    assert.ok(!mute.ok && mute.code === 'REFUSED');
    assert.deepEqual(await allowed.store.list(), []);
  });

  await test(`${backend}: break-glass pede auditor forensic, e um sink que falha o nega`, async () => {
    const standard = await setup({ rule: rule({ breakGlass: { maxDurationMs: HOUR } }), level: 'standard' });
    const low = await standard.flow.request(ask('e1', HOUR, { breakGlass: true }), current, { now: T0 });
    assert.ok(!low.ok && low.code === 'REFUSED');
    assert.deepEqual(low.violations.map((v) => v.invariant), ['break_glass_audit']);

    const broken = await setup({
      rule: rule({ breakGlass: { maxDurationMs: HOUR } }),
      hooks: {
        auditSink: () => {
          throw new Error('sink down');
        },
      },
    });
    const denied = await broken.flow.request(ask('e2', HOUR, { breakGlass: true }), current, { now: T0 });
    assert.ok(!denied.ok);
    assert.deepEqual(await broken.store.list(), []);
    assert.deepEqual(await broken.flow.active(T0 + 1), []);
  });

  await test(`${backend}: a elevação de papel vira atribuição de papel com janela`, async () => {
    const { Engine } = await load({ backend });
    const flow = new Elevations(new Engine(SPEC), new MemoryPendingStore(), {
      elevation: [{ key: { role: 'admin' }, maxDurationMs: HOUR, approverPermission: 'grants.manage', approverResource: project }],
      invariants,
    });
    await flow.request(ask('r1', HOUR, { target: { kind: 'role', role: 'admin' } }), current, { now: T0 });
    const done = await flow.approve('r1', admin('bia'), current, { now: T0 + 10 });
    assert.ok(done.ok);
    const mutation = done.request.mutation as { assign_role?: { role: { validFrom?: number; validUntil?: number } } };
    assert.equal(mutation.assign_role?.role.validFrom, T0 + 10);
    assert.equal(mutation.assign_role?.role.validUntil, T0 + 10 + HOUR);
  });

  await test(`${backend}: o JSON store guarda a elevação, a revogação e a revisão`, async (dir) => {
    const { Engine } = await load({ backend });
    const store = await openJsonStore({ path: join(dir, 'strig.json'), createIfMissing: true });
    await store.addGrant(adminGrant);
    const flow = new Elevations(new Engine(SPEC), store.pendingStore, {
      elevation: [rule({ breakGlass: { maxDurationMs: HOUR } })],
      invariants,
      audit: { level: 'forensic' },
    });
    const persist = async (result: { grants?: Grant[] }) => {
      for (const g of result.grants ?? []) if (g.id.startsWith('elevation:')) await store.addGrant(g);
    };
    const grants = async () => (await openJsonStore({ path: join(dir, 'strig.json') })).grants();

    const live = await flow.request(ask('e1', HOUR, { breakGlass: true }), await grants(), { now: T0, persist });
    assert.ok(live.ok);
    const reopened = await openJsonStore({ path: join(dir, 'strig.json') });
    assert.equal((await reopened.pendingStore.get('e1'))?.elevation?.review?.state, 'pending');
    assert.ok((await grants()).some((g) => g.id === 'elevation:e1'));

    await flow.closeReview('e1', admin('bia'), 'fine', await grants(), { now: T0 + 1 });
    const revoked = await flow.revoke('e1', ana, await grants(), {
      now: T0 + 2,
      persist: async (r) => void (await store.removeGrant('elevation:e1')),
    });
    assert.ok(revoked.ok);
    const after = await (await openJsonStore({ path: join(dir, 'strig.json') })).pendingStore.get('e1');
    assert.equal(after?.elevation?.review?.state, 'closed');
    assert.equal(after?.elevation?.revoked?.at, T0 + 2);
    assert.equal((await grants()).some((g) => g.id === 'elevation:e1'), false);
  });
}

if (failures > 0) process.exitCode = 1;
