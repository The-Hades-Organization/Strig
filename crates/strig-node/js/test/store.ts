// Tests of the JSON file store: atomic and concurrent writes, a crash between temp and rename, a corrupt or
// unknown-version file, reload, stale locks and the integration with `apply`. `run.js` imports this file.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { load } from '../dist/node.js';
import type { Grant } from '../dist/index.js';
import { JsonFileStore, JsonStoreError, openJsonStore } from '../dist/store.js';

let failures = 0;
async function test(name: string, fn: (dir: string) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), 'strig-store-'));
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
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const code = (expected: string) => (error: unknown) => {
  assert.ok(error instanceof JsonStoreError, `esperava JsonStoreError, veio ${String(error)}`);
  assert.equal(error.code, expected, error.message);
  return true;
};
const grant = (id: string, extra: Partial<Grant> = {}): Grant => ({
  id,
  subject: { kind: 'role', id: 'member' },
  permission: 'project.view',
  target: { kind: 'project' },
  effect: 'allow',
  ...extra,
});
const SPEC = {
  catalog: { targetKinds: ['project'], broadTargets: ['org'], permissions: [{ key: 'project.view', targets: ['project'] }] },
  roles: [{ role: 'member', inherits: [] }, { role: 'admin', inherits: ['member'] }],
};
const file = (dir: string) => join(dir, 'strig.json');
const seed = (dir: string, body: unknown = { version: 1, grants: [], roles: {} }) => writeFile(file(dir), JSON.stringify(body));

await test('load: arquivo ausente falha, createIfMissing cria vazio', async (dir) => {
  await assert.rejects(openJsonStore({ path: file(dir) }), code('STORE_NOT_FOUND'));
  const store = await openJsonStore({ path: file(dir), createIfMissing: true });
  assert.deepEqual(store.snapshot(), { version: 1, grants: [], roles: {} });
  assert.equal(JSON.parse(await readFile(file(dir), 'utf8')).version, 1);
});

await test('load: JSON corrompido e versão desconhecida falham fechado', async (dir) => {
  await writeFile(file(dir), '{"version":1,"grants":[');
  await assert.rejects(openJsonStore({ path: file(dir) }), code('STORE_CORRUPT'));
  await writeFile(file(dir), '');
  await assert.rejects(openJsonStore({ path: file(dir), createIfMissing: true }), code('STORE_CORRUPT'));
  await seed(dir, { version: 2, grants: [], roles: {} });
  await assert.rejects(openJsonStore({ path: file(dir) }), code('STORE_VERSION'));
  await seed(dir, { grants: [], roles: {} });
  await assert.rejects(openJsonStore({ path: file(dir) }), code('STORE_VERSION'));
  await seed(dir, { version: 1, grants: [{ id: 'a' }, { id: 'a' }], roles: {} });
  await assert.rejects(openJsonStore({ path: file(dir) }), code('STORE_CORRUPT'));
  await seed(dir, { version: 1, grants: {}, roles: {} });
  await assert.rejects(openJsonStore({ path: file(dir) }), code('STORE_CORRUPT'));
  assert.equal(await readFile(file(dir), 'utf8'), JSON.stringify({ version: 1, grants: {}, roles: {} }), 'o arquivo ruim não é tocado');
});

await test('grants e papéis: criar, mudar, apagar e ler de volta de outra instância', async (dir) => {
  await seed(dir);
  const store = await openJsonStore({ path: file(dir) });
  await store.addGrant(grant('g1'));
  await assert.rejects(store.addGrant(grant('g1')), code('STORE_INVALID'));
  await store.updateGrant(grant('g1', { effect: 'deny' }));
  await assert.rejects(store.updateGrant(grant('nope')), code('STORE_INVALID'));
  await store.assignRole('ana', { role: 'admin' });
  await store.assignRole('ana', { role: 'admin' });
  await store.assignRole('ana', { role: 'member', scope: { kind: 'project', id: 'p1' } });
  const other = await openJsonStore({ path: file(dir) });
  assert.equal(other.grants()[0]?.effect, 'deny');
  assert.equal(other.rolesOf('ana').length, 2);
  assert.deepEqual(other.subject({ kind: 'user', id: 'ana' }).roles?.map((r) => r.role), ['admin', 'member']);
  assert.equal(await store.revokeRole('ana', { role: 'admin' }), true);
  assert.equal(await store.revokeRole('ana', { role: 'admin' }), false);
  await store.setRoles('ana', []);
  assert.equal(await store.removeGrant('g1'), true);
  assert.equal(await store.removeGrant('g1'), false);
  assert.deepEqual((await openJsonStore({ path: file(dir) })).snapshot(), { version: 1, grants: [], roles: {} });
});

await test('escrita concorrente no mesmo processo não perde mudança', async (dir) => {
  await seed(dir);
  const store = await openJsonStore({ path: file(dir) });
  await Promise.all(Array.from({ length: 40 }, (_, i) => store.addGrant(grant(`g${i}`))));
  assert.equal((await openJsonStore({ path: file(dir) })).grants().length, 40);
  assert.deepEqual((await readdir(dir)).sort(), ['strig.json']);
});

await test('escrita concorrente entre processos não perde mudança', async (dir) => {
  await seed(dir);
  const script = `
    import { openJsonStore } from ${JSON.stringify(new URL('../dist/store.js', import.meta.url).href)};
    const store = await openJsonStore({ path: process.argv[1] });
    for (let i = 0; i < 15; i++) await store.addGrant({ id: process.argv[2] + i, subject: { kind: 'any' }, permission: 'project.view', target: { kind: 'project' }, effect: 'allow' });
  `;
  const bin = process.execPath;
  const run = (tag: string) =>
    new Promise<void>((done, fail) =>
      execFile(bin, ['--input-type=module', '-e', script, file(dir), tag], (error, _out, err) => (error ? fail(new Error(err)) : done())),
    );
  await Promise.all(['a', 'b', 'c'].map(run));
  const ids = new Set((await openJsonStore({ path: file(dir) })).grants().map((g) => g.id));
  assert.equal(ids.size, 45);
  assert.deepEqual((await readdir(dir)).sort(), ['strig.json']);
});

await test('crash entre o temp e o rename deixa o arquivo como estava', async (dir) => {
  await seed(dir);
  let crash = false;
  const store = await openJsonStore({
    path: file(dir),
    beforeRename: () => {
      if (crash) throw new Error('crash simulado');
    },
  });
  await store.addGrant(grant('g1'));
  const before = await readFile(file(dir), 'utf8');
  crash = true;
  await assert.rejects(store.addGrant(grant('g2')), /crash simulado/);
  assert.equal(await readFile(file(dir), 'utf8'), before, 'o arquivo não muda');
  assert.deepEqual((await readdir(dir)).sort(), ['strig.json'], 'nem sobra temp ou lock');
  assert.equal(store.grants().length, 1, 'o snapshot em memória também não muda');
  crash = false;
  await store.addGrant(grant('g2'));
  assert.equal((await openJsonStore({ path: file(dir) })).grants().length, 2);
});

await test('um temp deixado por um processo morto não atrapalha a carga', async (dir) => {
  await seed(dir, { version: 1, grants: [grant('g1')], roles: {} });
  await writeFile(`${file(dir)}.99999.deadbeef.tmp`, '{"version":1,"gra');
  const store = await openJsonStore({ path: file(dir) });
  assert.equal(store.grants().length, 1);
  await store.addGrant(grant('g2'));
  assert.equal((await openJsonStore({ path: file(dir) })).grants().length, 2);
});

await test('lock velho é tomado; lock vivo recente faz a escrita esperar e estourar', async (dir) => {
  await seed(dir);
  const lock = `${file(dir)}.lock`;
  await writeFile(lock, '999999999:other-host:token');
  const stale = await openJsonStore({ path: file(dir), lockStaleMs: 0 });
  await stale.addGrant(grant('g1'));
  assert.equal(stale.grants().length, 1);

  await writeFile(lock, `${process.pid}:${(await import('node:os')).hostname()}:vivo`);
  const waiting = await openJsonStore({ path: file(dir), lockTimeoutMs: 150 });
  await assert.rejects(waiting.addGrant(grant('g2')), code('STORE_LOCK_TIMEOUT'));
  assert.equal(await readFile(lock, 'utf8').then((t) => t.endsWith(':vivo')), true, 'o lock alheio fica');
  await rm(lock);

  await writeFile(lock, '999999999:' + (await import('node:os')).hostname() + ':morto');
  await waiting.addGrant(grant('g3'));
  assert.equal(waiting.grants().length, 2, 'dono morto neste host: tomado sem esperar o prazo');
});

await test('reload() lê a edição externa; arquivo ruim mantém o snapshot e avisa', async (dir) => {
  await seed(dir, { version: 1, grants: [grant('g1')], roles: {} });
  const store = await openJsonStore({ path: file(dir) });
  let changes = 0;
  store.onChange(() => (changes += 1));
  await seed(dir, { version: 1, grants: [grant('g1'), grant('g2')], roles: {} });
  assert.equal(store.grants().length, 1, 'sem reload o snapshot é o da carga');
  await store.reload();
  assert.equal(store.grants().length, 2);
  assert.equal(changes, 1);
  await writeFile(file(dir), 'lixo');
  await assert.rejects(store.reload(), code('STORE_CORRUPT'));
  assert.equal(store.grants().length, 2, 'o snapshot bom continua');
});

await test('watch() recarrega sozinho e reporta erro sem esvaziar', async (dir) => {
  await seed(dir);
  const store = await openJsonStore({ path: file(dir) });
  const errors: unknown[] = [];
  store.onError((e) => errors.push(e));
  const stop = store.watch(10);
  try {
    const other = await openJsonStore({ path: file(dir) });
    await other.addGrant(grant('g1'));
    for (let i = 0; i < 100 && store.grants().length === 0; i++) await sleep(20);
    assert.equal(store.grants().length, 1);
    await writeFile(file(dir), '{"version":');
    for (let i = 0; i < 100 && errors.length === 0; i++) await sleep(20);
    assert.ok(errors[0] instanceof JsonStoreError);
    assert.equal(store.grants().length, 1);
  } finally {
    stop();
  }
});

for (const backend of ['native', 'wasm'] as const) {
  await test(`${backend}: apply aprovado persiste, recusado não escreve; o store alimenta o provider`, async (dir) => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(SPEC);
    await seed(dir);
    const store = await openJsonStore({ path: file(dir) });
    const actor = { kind: 'user', id: 'root' };

    const added = await store.apply(engine, { actor, mutation: { add: grant('g1') } });
    assert.equal(added.ok, true);
    assert.equal((await openJsonStore({ path: file(dir) })).grants().length, 1);

    const bad = await store.apply(engine, {
      actor,
      mutation: { add: grant('g2', { permission: 'project.nope' }) },
      invariants: [{ kind: 'catalog_conformance' }],
    });
    assert.equal(bad.ok, false);
    assert.equal((await openJsonStore({ path: file(dir) })).grants().length, 1, 'recusa não escreve');

    const assigned = await store.apply(engine, { actor, mutation: { assign_role: { subject: { kind: 'user', id: 'ana' }, role: { role: 'admin' } } } });
    assert.equal(assigned.ok, true);
    assert.deepEqual((await openJsonStore({ path: file(dir) })).rolesOf('ana'), [{ role: 'admin' }]);

    const removed = await store.apply(engine, { actor, mutation: { remove: { id: 'g1' } } });
    assert.equal(removed.ok, true);
    const revoked = await store.apply(engine, { actor, mutation: { revoke_role: { subject: { kind: 'user', id: 'ana' }, role: { role: 'admin' } } } });
    assert.equal(revoked.ok, true);
    assert.deepEqual((await openJsonStore({ path: file(dir) })).snapshot(), { version: 1, grants: [], roles: {} });

    await store.addGrant(grant('g3'));
    const context = new Context({ grants: store.loadGrants() });
    await store.assignRole('ana', { role: 'member' });
    await sleep(0);
    const subject = store.subject({ kind: 'user', id: 'ana' });
    assert.equal(engine.check(context, { subject, permission: 'project.view', resource: { path: [{ kind: 'project', id: 'p1' }] } }), true);
  });
}

if (failures) console.log(`# store: ${failures} falha(s)`);
