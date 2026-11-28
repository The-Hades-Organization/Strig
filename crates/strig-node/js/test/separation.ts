// Separação de funções no binding: o catálogo carrega os conjuntos e as regras, o invariante recusa o
// acúmulo e a decisão nega quem fez a primeira ação no mesmo recurso. Roda nos dois alvos.
import assert from 'node:assert/strict';
import { load, scopeFromString } from '../dist/node.js';
import type { ApplyInput, Grant, Subject } from '../dist/index.js';

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

const SPEC = {
  catalog: {
    targetKinds: ['org', 'payment'],
    broadTargets: [],
    permissions: [
      { key: 'payment.create', targets: ['payment'] },
      { key: 'payment.approve', targets: ['payment'] },
    ],
    mutuallyExclusive: [{ name: 'payment_duties', of: 'roles', members: ['maker', 'checker'], anchor: 'org' }],
    conflictingActions: [{ name: 'four_eyes', first: ['payment.create'], then: ['payment.approve'] }],
  },
  roles: [{ role: 'lead', inherits: ['checker'] }],
};
const user = (id: string, roles: { role: string; scope?: unknown }[] = []): Subject => ({ kind: 'user', id, roles }) as Subject;
const org = (id: string) => ({ kind: 'org', id });
const assign = (subject: Subject, role: string, scope: unknown): ApplyInput['mutation'] =>
  ({ assign_role: { subject, role: { role, scope } } }) as ApplyInput['mutation'];

for (const backend of ['native', 'wasm'] as const) {
  const { Engine, Context } = await load({ backend });
  const tag = (name: string) => `${backend}: ${name}`;

  await test(tag('o invariante recusa o papel que completa o conjunto, também por herança'), () => {
    const engine = new Engine(SPEC);
    const ana = user('ana', [{ role: 'maker', scope: org('o1') }]);
    for (const role of ['checker', 'lead']) {
      const out = engine.apply({
        actor: user('admin'),
        current: [],
        mutation: assign(ana, role, org('o1')),
        invariants: [{ kind: 'separation_of_duties' }],
      });
      assert.equal(out.ok, false, role);
      assert.equal(out.violations?.[0]?.invariant, 'separation_of_duties');
      assert.match(out.violations?.[0]?.message ?? '', /payment_duties/);
    }
    const other = engine.apply({
      actor: user('admin'),
      current: [],
      mutation: assign(ana, 'checker', org('o2')),
      invariants: [{ kind: 'separation_of_duties' }],
    });
    assert.equal(other.ok, true, 'outra organização não conflita');
  });

  await test(tag('a decisão nega quem fez a primeira ação no mesmo recurso'), () => {
    const engine = new Engine(SPEC);
    const approve: Grant = {
      id: 'approve',
      effect: 'allow',
      subject: { kind: 'role', id: 'checker' },
      permission: 'payment.approve',
      target: { kind: 'payment' },
    };
    const ctx = new Context({ grants: [approve] });
    const resource = { ...scopeFromString('payment:p1/org:o1'), attrs: { history: ['payment.create:ana'] } };
    const ana = user('ana', [{ role: 'checker' }]);
    const bia = user('bia', [{ role: 'checker' }]);
    assert.equal(engine.check(ctx, { subject: ana, permission: 'payment.approve', resource }), false);
    assert.equal(engine.check(ctx, { subject: bia, permission: 'payment.approve', resource }), true);
    assert.equal(engine.decide(ctx, { subject: ana, permission: 'payment.approve', resource }).reason.kind, 'override');
  });

  await test(tag('o impacto lista o conflito mesmo sem o invariante'), () => {
    const engine = new Engine(SPEC);
    const ana = user('ana', [{ role: 'maker', scope: org('o1') }]);
    const out = engine.apply({ actor: user('admin'), current: [], mutation: assign(ana, 'checker', org('o1')), impact: {} });
    assert.equal(out.ok, true);
    assert.equal((out as { impact?: { separation?: { clash: { set: string } }[] } }).impact?.separation?.[0]?.clash.set, 'payment_duties');
  });
}
if (failures > 0) process.exitCode = 1;
