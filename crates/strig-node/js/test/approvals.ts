// Approval flow: propose, approve or refuse by another actor, expiry, audit trail and the JSON store.
// Runs on both backends (N-API and wasm); `run.js` imports this file.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Approvals, MemoryPendingStore, PendingStoreError } from '../dist/approvals.js';
import type { ApplyInput, ApprovalRule, EngineHooks, Grant, InvariantSpec, Subject } from '../dist/index.js';
import { load } from '../dist/node.js';
import { openJsonStore } from '../dist/store.js';

let failures = 0;
async function test(name: string, fn: (dir: string) => unknown) {
  const dir = await mkdtemp(join(tmpdir(), 'strig-approvals-'));
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
const T0 = 1_700_000_000_000;
const project = { path: [{ kind: 'project', id: 'p1' }] };
const admin = (id: string): Subject => ({ kind: 'user', id, roles: [{ role: 'admin' }] });
const adminGrant: Grant = { id: 'adm', subject: { kind: 'role', id: 'admin' }, permission: 'grants.manage', target: { kind: 'project' }, effect: 'allow' };
const grant = (id: string): Grant => ({ id, subject: { kind: 'any' }, permission: 'project.view', target: { kind: 'project' }, effect: 'allow' });
const add = (id: string): ApplyInput['mutation'] => ({ add: grant(id) });
const approval: ApprovalRule[] = [{ kind: 'add', permission: 'grants.manage', resource: project }];
const invariants: InvariantSpec[] = [
  { kind: 'catalog_conformance' },
  { kind: 'require_permission', permission: 'grants.manage', resource: project },
  { kind: 'no_self_management' },
];

for (const backend of ['native', 'wasm'] as const) {
  const setup = async (extra: { audit?: ApplyInput['audit']; hooks?: EngineHooks } = {}) => {
    const { Engine } = await load({ backend });
    const store = new MemoryPendingStore();
    const flow = new Approvals(new Engine(SPEC, extra.hooks), store, { approval, invariants, ...(extra.audit ? { audit: extra.audit } : {}) });
    return { flow, store };
  };

  await test(`${backend}: uma mudança coberta pela política espera; a que não é, aplica na hora`, async () => {
    const { flow, store } = await setup();
    const waiting = await flow.propose(admin('ana'), add('g1'), [adminGrant], { id: 'r1', now: T0, expiresAt: T0 + 500 });
    assert.ok(waiting.ok && !waiting.applied);
    assert.equal(waiting.request.status.state, 'pending');
    assert.equal(waiting.request.expiresAt, T0 + 500);
    assert.deepEqual((await flow.pending(T0)).map((r) => r.id), ['r1']);

    const direct = await flow.propose(admin('ana'), { remove: { id: 'g2' } }, [adminGrant, grant('g2')], { id: 'r2', now: T0 });
    assert.ok(direct.ok && direct.applied);
    assert.equal(await store.get('r2'), undefined);
    await assert.rejects(flow.propose(admin('ana'), add('g3'), [adminGrant], { id: 'r1', now: T0 }), (e: unknown) => e instanceof PendingStoreError && e.code === 'PENDING_DUPLICATE');
  });

  await test(`${backend}: o autor nunca aprova o próprio pedido, nem quem não tem a permissão`, async () => {
    const { flow, store } = await setup();
    await flow.propose(admin('ana'), add('g1'), [adminGrant], { id: 'r1', now: T0 });

    const own = await flow.approve('r1', admin('ana'), [adminGrant], { now: T0 + 1 });
    assert.ok(!own.ok && own.code === 'REFUSED');
    assert.equal(own.violations[0]?.invariant, 'no_self_approval');
    const sameIdOtherKind = await flow.approve('r1', { kind: 'service', id: 'ana', roles: [{ role: 'admin' }] }, [adminGrant], { now: T0 + 1 });
    assert.ok(!sameIdOtherKind.ok && sameIdOtherKind.code === 'REFUSED');
    const member = await flow.approve('r1', { kind: 'user', id: 'bia' }, [adminGrant], { now: T0 + 1 });
    assert.ok(!member.ok && member.code === 'REFUSED');
    assert.equal(member.violations[0]?.invariant, 'require_approval_permission');
    assert.equal((await store.get('r1'))?.status.state, 'pending');
  });

  await test(`${backend}: outro ator aprova; a governança roda de novo sobre o estado atual`, async () => {
    const { flow, store } = await setup();
    await flow.propose(admin('ana'), add('g1'), [adminGrant], { id: 'r1', now: T0 });

    const changed = await flow.approve('r1', admin('caio'), [adminGrant, grant('g1')], { now: T0 + 1 });
    assert.ok(!changed.ok && changed.code === 'REFUSED');
    assert.equal(changed.violations[0]?.invariant, 'mutation');
    assert.equal((await store.get('r1'))?.status.state, 'pending');

    let persisted: Grant[] | undefined;
    const done = await flow.approve('r1', admin('caio'), [adminGrant], { now: T0 + 2, persist: (r) => void (persisted = r.grants) });
    assert.ok(done.ok);
    assert.equal(persisted?.length, 2);
    assert.deepEqual((await store.get('r1'))?.status, { state: 'approved', by: 'caio', at: T0 + 2 });
    const again = await flow.approve('r1', admin('caio'), [adminGrant], { now: T0 + 3 });
    assert.ok(!again.ok && again.code === 'NOT_PENDING');
  });

  await test(`${backend}: recusa exige motivo e fecha o pedido`, async () => {
    const { flow, store } = await setup();
    await flow.propose(admin('ana'), add('g1'), [adminGrant], { id: 'r1', now: T0 });
    const empty = await flow.reject('r1', admin('caio'), ' ', [adminGrant], { now: T0 + 1 });
    assert.ok(!empty.ok && empty.code === 'REFUSED');
    const done = await flow.reject('r1', admin('caio'), 'fora da janela', [adminGrant], { now: T0 + 2 });
    assert.ok(done.ok);
    assert.deepEqual((await store.get('r1'))?.status, { state: 'rejected', by: 'caio', at: T0 + 2, reason: 'fora da janela' });
  });

  await test(`${backend}: o pedido expira e não se decide depois`, async () => {
    const { flow, store } = await setup();
    await flow.propose(admin('ana'), add('a'), [adminGrant], { id: 'due', now: T0, expiresAt: T0 + 100 });
    await flow.propose(admin('ana'), add('b'), [adminGrant], { id: 'late', now: T0, expiresAt: T0 + 900 });
    await flow.propose(admin('ana'), add('c'), [adminGrant], { id: 'never', now: T0 });

    assert.equal((await flow.pending(T0 + 100)).length, 2);
    const swept = await flow.expire({ now: T0 + 100 });
    assert.deepEqual(swept.expired.map((r) => r.id), ['due']);
    assert.deepEqual((await store.get('due'))?.status, { state: 'expired', at: T0 + 100 });
    assert.equal((await flow.expire({ now: T0 + 100 })).expired.length, 0);

    const late = await flow.approve('late', admin('caio'), [adminGrant], { now: T0 + 900 });
    assert.ok(!late.ok && late.code === 'EXPIRED');
    assert.deepEqual((await store.get('late'))?.status, { state: 'expired', at: T0 + 900 });
    assert.ok((await flow.approve('never', admin('caio'), [adminGrant], { now: T0 + 5_000 })).ok);
  });

  await test(`${backend}: uma mudança de papel também é pedido e devolve o sujeito a gravar`, async () => {
    const { Engine } = await load({ backend });
    const flow = new Approvals(new Engine(SPEC), new MemoryPendingStore(), { approval: [{ kind: 'assign_role', permission: 'grants.manage', resource: project }] });
    const change: ApplyInput['mutation'] = { assign_role: { subject: { kind: 'user', id: 'dani' }, role: { role: 'admin' } } };
    const waiting = await flow.propose(admin('ana'), change, [adminGrant], { id: 'r1', now: T0 });
    assert.ok(waiting.ok && !waiting.applied);
    assert.deepEqual(waiting.request.mutation, change);
    const done = await flow.approve('r1', admin('caio'), [adminGrant], { now: T0 + 1 });
    assert.ok(done.ok);
    assert.deepEqual(done.subject?.roles, [{ role: 'admin' }]);
  });

  await test(`${backend}: cada passo deixa registro e a cadeia continua entre as chamadas`, async () => {
    const records: Array<Record<string, unknown>> = [];
    const { flow } = await setup({ audit: { level: 'forensic' }, hooks: { auditSink: (record) => void records.push(record) } });
    const { verifyAuditChain } = await load({ backend });
    const keep = <T>(result: T) => result;

    keep(await flow.propose(admin('ana'), add('g1'), [adminGrant], { id: 'r1', now: T0, expiresAt: T0 + 50 }));
    keep(await flow.approve('r1', admin('ana'), [adminGrant], { now: T0 + 1 }));
    keep(await flow.approve('r1', admin('caio'), [adminGrant], { now: T0 + 2 }));
    keep(await flow.propose(admin('ana'), add('g2'), [adminGrant], { id: 'r2', now: T0 + 3 }));
    keep(await flow.reject('r2', admin('caio'), 'duplicado', [adminGrant], { now: T0 + 4 }));
    keep(await flow.propose(admin('ana'), add('g3'), [adminGrant], { id: 'r3', now: T0 + 5, expiresAt: T0 + 6 }));
    keep(await flow.expire({ now: T0 + 6 }));

    assert.deepEqual(
      records.map((r) => [r.action, r.outcome]),
      [
        ['mutation_propose', 'pending'],
        ['mutation_approve', 'rejected'],
        ['mutation_approve', 'applied'],
        ['grant_add', 'applied'],
        ['mutation_propose', 'pending'],
        ['mutation_reject', 'applied'],
        ['mutation_propose', 'pending'],
        ['mutation_expire', 'applied'],
      ],
    );
    assert.deepEqual(verifyAuditChain(records), { ok: true, head: records.at(-1)?.hash });
    assert.equal(records[0]?.pending && (records[0].pending as { expires_at: number }).expires_at, T0 + 50);
    const refused = records[1] as { actor: string; pending: { id: string; author: string }; violations: string[] };
    assert.deepEqual([refused.actor, refused.pending.id, refused.pending.author], ['ana', 'r1', 'ana']);
    assert.equal(refused.violations.length, 1);
    assert.equal((records[5] as { pending: { reason: string } }).pending.reason, 'duplicado');
    assert.equal(records[7]?.actor, 'strig-expiry');
  });

  await test(`${backend}: o store JSON guarda os pedidos e persiste as grants antes de marcar aprovado`, async (dir) => {
    const { Engine } = await load({ backend });
    const path = join(dir, 'grants.json');
    await writeFile(path, JSON.stringify({ version: 1, grants: [adminGrant], roles: {} }));
    const store = await openJsonStore({ path });
    const flow = new Approvals(new Engine(SPEC), store.pendingStore, { approval, invariants });
    await flow.propose(admin('ana'), add('g1'), store.grants(), { id: 'r1', now: T0 });
    assert.equal(JSON.parse(await readFile(path, 'utf8')).pending[0].id, 'r1');

    const reopened = await openJsonStore({ path });
    const again = new Approvals(new Engine(SPEC), reopened.pendingStore, { approval, invariants });
    assert.deepEqual((await again.pending(T0)).map((r) => r.id), ['r1']);
    const own = await reopened.approvePending(again, 'r1', admin('ana'), { now: T0 + 1 });
    assert.ok(!own.ok);
    assert.equal(reopened.grants().length, 1);

    const done = await reopened.approvePending(again, 'r1', admin('caio'), { now: T0 + 2 });
    assert.ok(done.ok);
    const saved = JSON.parse(await readFile(path, 'utf8'));
    assert.equal(saved.grants.length, 2);
    assert.equal(saved.pending[0].status.state, 'approved');
    await assert.rejects(async () => reopened.pendingStore.update(saved.pending[0]), (e: unknown) => e instanceof PendingStoreError && e.code === 'PENDING_NOT_PENDING');
  });

  await test(`${backend}: o impacto fica no pedido e é recalculado sobre o estado atual`, async () => {
    const { Engine } = await load({ backend });
    const store = new MemoryPendingStore();
    const impact = { source: { kind: 'sample' as const, subjects: [{ kind: 'user', id: 'bia' }], resources: [project] } };
    const flow = new Approvals(new Engine(SPEC), store, { approval, invariants, impact });
    const waiting = await flow.propose(admin('ana'), add('g1'), [adminGrant], { id: 'r1', now: T0 });
    assert.ok(waiting.ok && !waiting.applied);
    assert.equal(waiting.request.impact?.gained[0]?.subject, 'user:bia');
    assert.equal((await store.get('r1'))?.impact?.gained.length, 1);

    const same = await flow.reviewImpact('r1', [adminGrant], { now: T0 + 1 });
    assert.equal(same.changed, false);
    const moved = [adminGrant, { ...grant('other') }];
    const review = await flow.reviewImpact('r1', moved, { now: T0 + 1 });
    assert.equal(review.changed, true);
    assert.equal(review.current?.gained.length, 0, 'bia already had it');
    assert.equal(review.proposed?.gained.length, 1);

    const done = await flow.approve('r1', admin('caio'), moved, { now: T0 + 2 });
    assert.ok(done.ok);
    assert.equal(done.proposedImpact?.gained.length, 1);
    assert.equal(done.request.impact?.gained.length, 0, 'the approval recomputed it');
  });

  await test(`${backend}: arquivo de uma versão anterior, sem pedidos, abre e segue como estava`, async (dir) => {
    const path = join(dir, 'old.json');
    await writeFile(path, JSON.stringify({ version: 1, grants: [adminGrant], roles: {} }));
    const store = await openJsonStore({ path });
    assert.deepEqual(await store.pendingStore.list(), []);
    await store.addGrant(grant('g9'));
    assert.equal('pending' in JSON.parse(await readFile(path, 'utf8')), false);
  });
}

if (failures > 0) process.exitCode = 1;
