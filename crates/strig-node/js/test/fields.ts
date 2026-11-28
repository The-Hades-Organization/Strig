// Permissão por campo: `allowedFields`, `field` no pedido (nas duas vias, objeto e texto), o
// rastro por campo, a máscara `pickAllowed` e o formato de capacidades para leitores antigos. Roda nos
// dois alvos (N-API e wasm); `run.js` importa este arquivo.
import assert from 'node:assert/strict';
import { load, scopeFromString, pickAllowed } from '../dist/node.js';
import type { BindingError, DecisionRequest, FieldSet, Grant, Subject } from '../dist/index.js';

let failures = 0;
async function test(name: string, fn: () => unknown) {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failures += 1;
    process.exitCode = 1;
    console.log(`not ok - ${name}\n  ${error instanceof Error ? error.stack : error}`);
  }
}

const spec = (declare: boolean) => ({
  catalog: {
    targetKinds: ['project'],
    permissions: [
      { key: 'doc.view', targets: ['project'] },
      { key: 'doc.edit', targets: ['project'], dependsOn: ['doc.view'], ...(declare ? { fields: ['title', 'body', 'status'] } : {}) },
    ],
  },
});
const NOW = 1_704_110_400_000;
const p1 = scopeFromString('project:p1');
const ana: Subject = { kind: 'user', id: 'ana', roles: [{ role: 'editor' }] };
const grant = (id: string, permission: string, effect: 'allow' | 'deny', fields?: string[]): Grant => ({
  id,
  subject: { kind: 'role', id: 'editor' },
  permission,
  target: { kind: 'project' },
  effect,
  ...(fields ? { fields } : {}),
});
const ask = (permission: string, field?: string): DecisionRequest => ({ subject: ana, permission, resource: p1, ...(field ? { field } : {}) });
const grants = [grant('view', 'doc.view', 'allow'), grant('edit', 'doc.edit', 'allow'), grant('lock', 'doc.edit', 'deny', ['status'])];

for (const backend of ['native', 'wasm'] as const) {
  await test(`${backend}: allowedFields lista o que o editor pode mexer`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec(true));
    const ctx = new Context({ grants, now: NOW });
    assert.deepEqual(engine.allowedFields(ctx, ask('doc.edit')), { kind: 'only', fields: ['body', 'title'] });
    assert.deepEqual(engine.allowedFields(ctx, ask('doc.view')), { kind: 'all' });
    assert.deepEqual(engine.allowedFields(ctx, ask('doc.nope')), { kind: 'none' });
  });

  await test(`${backend}: sem campos declarados, o resto vem como all_except`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec(false));
    const ctx = new Context({ grants, now: NOW });
    assert.deepEqual(engine.allowedFields(ctx, ask('doc.edit')), { kind: 'all_except', fields: ['status'] });
  });

  await test(`${backend}: o campo do pedido vale em check, decide e explain, pelo objeto e pelo texto`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec(true));
    const ctx = new Context({ grants, now: NOW });
    assert.equal(engine.check(ctx, ask('doc.edit', 'title')), true);
    assert.equal(engine.check(ctx, ask('doc.edit', 'status')), false);
    assert.equal(engine.check(ctx, ask('doc.edit', 'bogus')), false, 'campo fora do catálogo nega');
    assert.equal(engine.check(ctx, ask('doc.edit')), false, 'o recurso inteiro inclui o campo negado');
    const slow = Object.assign(Object.create({}), { ...ask('doc.edit', 'status'), subject: Object.assign(new (class Boxed {})(), ana) });
    assert.equal(engine.check(ctx, slow), false);
    assert.deepEqual(engine.checkMany(ctx, [ask('doc.edit', 'title'), ask('doc.edit', 'status')]), [true, false]);
    const explanation = engine.explain(ctx, ask('doc.edit', 'status'));
    assert.equal(explanation.field, 'status');
    assert.equal(explanation.decision.effect, 'deny');
  });

  await test(`${backend}: explainFields diz quem deu e quem tirou cada campo`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec(true));
    const ctx = new Context({ grants, now: NOW });
    const explanation = engine.explainFields(ctx, ask('doc.edit'));
    const status = explanation.fields.find((f) => f.field === 'status')!;
    assert.equal(status.allowed, false);
    assert.deepEqual(status.grantedBy, ['edit']);
    assert.deepEqual(status.deniedBy, ['lock']);
    assert.deepEqual(explanation.fields.find((f) => f.field === 'title')!.deniedBy ?? [], []);
  });

  await test(`${backend}: um grant com campo que o catálogo não declara é recusado`, async () => {
    const { Engine } = await load({ backend });
    const engine = new Engine(spec(true));
    engine.validateGrant(grant('g', 'doc.edit', 'allow', ['title']));
    assert.throws(() => engine.validateGrant(grant('g', 'doc.edit', 'allow', ['titel'])), (e: BindingError) => /titel/.test(e.message));
  });

  await test(`${backend}: capacidades com campos levam a forma segura e a real, e decidem iguais depois de recarregadas`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec(true));
    const ctx = new Context({ grants: [grant('view', 'doc.view', 'allow'), grant('edit', 'doc.edit', 'allow', ['title'])], now: NOW });
    const set = engine.capabilities(ctx, ana, p1);
    assert.deepEqual(set.grants.map((g) => g.id), ['view'], 'o leitor antigo não vê allow com campo');
    assert.equal(set.withFields?.length, 2);
    const loaded = new Context({ now: NOW });
    loaded.loadCapabilities(JSON.parse(JSON.stringify(set)));
    assert.deepEqual(engine.allowedFields(loaded, ask('doc.edit')), { kind: 'only', fields: ['title'] });
    const plain = engine.capabilities(new Context({ grants: [grant('view', 'doc.view', 'allow')], now: NOW }), ana, p1);
    assert.equal('withFields' in plain, false, 'sem campos o formato é o de sempre');
  });
}

await test('pickAllowed mascara a resposta pelos campos permitidos', () => {
  const doc = { title: 'a', body: 'b', status: 'draft', address: { street: 's', city: 'c' } };
  const only = (...fields: string[]): FieldSet => ({ kind: 'only', fields });
  assert.deepEqual(pickAllowed(doc, only('title', 'body')), { title: 'a', body: 'b' });
  assert.deepEqual(pickAllowed(doc, only('address.street')), { address: { street: 's' } });
  assert.deepEqual(pickAllowed(doc, only('address')), { address: { street: 's', city: 'c' } });
  assert.deepEqual(pickAllowed(doc, { kind: 'all' }), doc);
  assert.deepEqual(pickAllowed(doc, { kind: 'none' }), {});
  assert.deepEqual(pickAllowed(doc, { kind: 'all_except', fields: ['status', 'address.city'] }), {
    title: 'a',
    body: 'b',
    address: { street: 's' },
  });
  assert.equal(doc.address.city, 'c', 'a entrada não muda');
  assert.deepEqual(pickAllowed(doc, only('missing', '__proto__.x', 'constructor')), {});
  assert.equal(({} as Record<string, unknown>).x, undefined);
});

if (failures) console.log(`# fields: ${failures} falha(s)`);
