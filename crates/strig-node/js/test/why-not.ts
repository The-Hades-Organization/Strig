// `engine.whyNot`: as mudanças verificadas que permitiriam um pedido negado. Roda nos dois alvos
// (N-API e wasm); `run.js` importa este arquivo.
import assert from 'node:assert/strict';
import { load, scopeFromString } from '../dist/node.js';
import type { BindingError, DecisionRequest, Grant, Remedy, Subject } from '../dist/index.js';

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

const spec = (extra: object = {}) => ({
  catalog: {
    targetKinds: ['project'],
    permissions: [
      { key: 'doc.view', targets: ['project'] },
      { key: 'doc.admin', targets: ['project'], managementOnly: true },
    ],
  },
  ...extra,
});
const NOW = 1_704_110_400_000;
const p1 = scopeFromString('project:p1');
const ana: Subject = { kind: 'user', id: 'ana' };
const viewerGrant: Grant = {
  id: 'r',
  subject: { kind: 'role', id: 'viewer' },
  permission: 'doc.view',
  target: { kind: 'project' },
  effect: 'allow',
};
const as = <K extends Remedy['kind']>(remedy: Remedy | undefined, kind: K): Extract<Remedy, { kind: K }> => {
  assert.equal(remedy?.kind, kind);
  return remedy as Extract<Remedy, { kind: K }>;
};
const ask = (permission: string, subject: Subject = ana): DecisionRequest => ({ subject, permission, resource: p1 });

for (const backend of ['native', 'wasm'] as const) {
  await test(`${backend}: whyNot sugere grant e papel verificados, o menor primeiro`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec());
    const ctx = new Context({ grants: [viewerGrant], now: NOW });
    const answer = engine.whyNot(ctx, ask('doc.view'))!;
    assert.deepEqual(answer.cause, { kind: 'no_applicable_grant' });
    assert.deepEqual(answer.remedies.map((r) => r.kind), ['add_grant', 'add_grant', 'assign_role']);
    assert.equal(as(answer.remedies[0], 'add_grant').grant.target.id, 'p1');
    const role = as(answer.remedies[2], 'assign_role');
    assert.equal(role.role, 'viewer');
    assert.equal(role.scope?.id, 'p1');
    for (const remedy of answer.remedies) {
      const subject = remedy.kind === 'assign_role' ? { ...ana, roles: [{ role: remedy.role, scope: remedy.scope }] } : ana;
      const grants = remedy.kind === 'add_grant' ? [viewerGrant, remedy.grant] : [viewerGrant];
      assert.equal(engine.check(new Context({ grants, now: NOW }), ask('doc.view', subject)), true, JSON.stringify(remedy));
    }
  });

  await test(`${backend}: whyNot devolve null quando o pedido já é permitido`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec());
    const ctx = new Context({ grants: [viewerGrant], now: NOW });
    assert.equal(engine.whyNot(ctx, ask('doc.view', { ...ana, roles: [{ role: 'viewer' }] })), null);
  });

  await test(`${backend}: whyNot nomeia o deny que decidiu e marca o que é compartilhado e o governo do catálogo`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec());
    const deny: Grant = { id: 'd', subject: { kind: 'any' }, permission: 'doc.view', target: { kind: 'project', id: 'p1' }, effect: 'deny' };
    const own: Grant = { ...viewerGrant, id: 'a', subject: { kind: 'user', id: 'ana' } };
    const answer = engine.whyNot(new Context({ grants: [own, deny], now: NOW }), ask('doc.view'))!;
    assert.equal(answer.cause.kind, 'deny');
    assert.equal(answer.cause.kind === 'deny' && answer.cause.grantId, 'd');
    assert.deepEqual(answer.remedies.map((r) => r.kind), ['remove_deny']);
    assert.deepEqual(answer.remedies[0]?.caveats, ['affects_others']);

    const admin = engine.whyNot(new Context({ grants: [], now: NOW }), ask('doc.admin'))!;
    assert.ok(admin.remedies.length > 0);
    assert.ok(admin.remedies.every((r) => r.caveats?.includes('management_only')));
  });

  await test(`${backend}: whyNot diz o que falhou na condição sem inventar valor`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec());
    const conditional: Grant = {
      ...viewerGrant,
      id: 'c',
      subject: { kind: 'user', id: 'ana' },
      condition: { op: 'eq', left: { attr: 'subject.plan' }, right: 'pro' },
    };
    const answer = engine.whyNot(new Context({ grants: [conditional], now: NOW }), ask('doc.view', { ...ana, attrs: { plan: 'free' } }))!;
    const first = as(answer.remedies[0], 'satisfy_condition');
    assert.equal(first.grantId, 'c');
    assert.deepEqual(first.failed, ['subject.plan ("free") = "pro"']);
  });

  await test(`${backend}: whyNot de um override diz qual e não oferece remédio`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec(), {
      overrides: [{ name: 'suspended', evaluate: (request) => (request.subject.id === 'ana' ? 'denied' : undefined) }],
    });
    const answer = engine.whyNot(new Context({ grants: [viewerGrant], now: NOW }), ask('doc.view'))!;
    assert.deepEqual(answer.cause, { kind: 'override', name: 'suspended' });
    assert.deepEqual(answer.remedies, []);
  });

  await test(`${backend}: o limite de verificações e maxRemedies marcam o resultado como parcial`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(spec());
    const ctx = new Context({ grants: [viewerGrant], now: NOW });
    const cut = engine.whyNot(ctx, ask('doc.view'), undefined, { maxRemedies: 1 })!;
    assert.equal(cut.remedies.length, 1);
    assert.equal(cut.partial, true);
    const none = engine.whyNot(ctx, ask('doc.view'), undefined, { maxDecisions: 0 })!;
    assert.deepEqual(none.remedies, []);
    assert.equal(none.partial, true);
    ctx.setLimits({ maxDecisions: 0 });
    assert.equal(engine.whyNot(ctx, ask('doc.view'))!.partial, true, 'o limite do contexto vale');
    assert.throws(
      () => engine.whyNot(ctx, ask('doc.view'), undefined, { bogus: 1 } as never),
      (e: BindingError) => e.code === 'INVALID_INPUT',
    );
  });
}

if (failures) console.log(`# why-not: ${failures} falha(s)`);
