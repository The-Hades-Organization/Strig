// Fast path (string crossing) and batches: `check`/`decide`/`explain` must answer the same as the
// original object path, `checkMany`/`explainMany` the same as one call per request, and the
// incremental changes of a `Context` must show in the next decision. Roda nos dois alvos (N-API e
// wasm); `run.js` importa este arquivo.
import assert from 'node:assert/strict';
import { load, scopeFromString } from '../dist/node.js';
import type { BindingError, DecisionRequest, Grant, Subject } from '../dist/index.js';

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
const code = (expected: string) => (error: BindingError) => {
  assert.equal(error.code, expected, `code esperado ${expected}, veio ${error.code}: ${error.message}`);
  return true;
};

const SPEC = {
  catalog: {
    targetKinds: ['project'],
    broadTargets: ['org'],
    permissions: [
      { key: 'project.view', targets: ['project'] },
      { key: 'project.edit', targets: ['project'] },
    ],
  },
};
const NOW = 1_704_110_400_000;
const p1 = scopeFromString('project:p1/org:o1');
const p2 = scopeFromString('project:p2/org:o1');
const ana: Subject = { kind: 'user', id: 'ana', roles: [{ role: 'member' }], attrs: { dept: 'eng' } };
const grant = (id: string, extra: Partial<Grant> = {}): Grant => ({
  id,
  subject: { kind: 'role', id: 'member' },
  permission: 'project.view',
  target: { kind: 'project' },
  effect: 'allow',
  ...extra,
});
// A class instance is not plain JSON: a request holding one takes the original object path.
class Boxed {}
const boxed = <T extends object>(value: T): T => Object.assign(new Boxed(), value);
const request = (permission: string, resource = p1, subject = ana): DecisionRequest => ({ subject, permission, resource });
const requests = [
  request('project.view'),
  request('project.edit'),
  request('project.view', p2),
  request('project.view', p1, { kind: 'user', id: 'bob' }),
];

for (const backend of ['native', 'wasm'] as const) {
  await test(`${backend}: check, decide e explain pelo texto dão o mesmo que o caminho por objeto`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(SPEC);
    const ctx = new Context({ grants: [grant('v'), grant('d', { effect: 'deny', target: { kind: 'project', id: 'p2' } })], now: NOW });
    for (const req of requests) {
      const slow = boxed({ ...req, subject: boxed(req.subject) });
      assert.equal(engine.check(ctx, req), engine.check(ctx, slow));
      assert.deepEqual(engine.decide(ctx, req), engine.decide(ctx, slow));
      assert.deepEqual(engine.explain(ctx, req), engine.explain(ctx, slow));
    }
    assert.equal(engine.check(ctx, requests[0]!), true);
    assert.equal(engine.check(ctx, requests[2]!), false);
    assert.equal(engine.decide(ctx, requests[2]!).effect, 'deny');
  });

  await test(`${backend}: checkMany e explainMany dão o mesmo que uma chamada por pedido, na ordem`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(SPEC);
    const ctx = new Context({ grants: [grant('v')], now: NOW });
    assert.deepEqual(engine.checkMany(ctx, requests), requests.map((r) => engine.check(ctx, r)));
    assert.deepEqual(engine.checkMany(ctx, requests), [true, false, true, false]);
    assert.deepEqual(engine.explainMany(ctx, requests), requests.map((r) => engine.explain(ctx, r)));
    assert.deepEqual(engine.checkMany(ctx, []), []);
    assert.deepEqual(engine.explainMany(ctx, []), []);
    const odd = requests.map((r) => boxed({ ...r, subject: boxed(r.subject) }));
    assert.deepEqual(engine.checkMany(ctx, odd), engine.checkMany(ctx, requests), 'o caminho por objeto dá o mesmo');
  });

  await test(`${backend}: o now da chamada vale em lote e vence o do Context; sem now falha fechado`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(SPEC);
    const windowed = grant('w', { validFrom: NOW - 1000, validUntil: NOW + 1000 } as Partial<Grant>);
    const ctx = new Context({ grants: [windowed] });
    assert.deepEqual(engine.checkMany(ctx, [requests[0]!]), [false], 'sem instante, a janela nega');
    assert.deepEqual(engine.checkMany(ctx, [requests[0]!], NOW), [true]);
    assert.deepEqual(engine.checkMany(ctx, [requests[0]!], NOW + 5000), [false]);
    ctx.setNow(NOW);
    assert.deepEqual(engine.checkMany(ctx, [requests[0]!]), [true]);
    assert.deepEqual(engine.checkMany(ctx, [requests[0]!], NOW + 5000), [false], 'o now da chamada vence');
  });

  await test(`${backend}: add, remove e replace mudam a decisão seguinte sem reenviar o resto`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(SPEC);
    const ctx = new Context({ grants: [grant('v')], now: NOW });
    assert.equal(engine.check(ctx, requests[1]!), false);
    ctx.addGrant(grant('e', { permission: 'project.edit' }));
    assert.deepEqual(engine.checkMany(ctx, requests.slice(0, 2)), [true, true]);
    ctx.addGrant(grant('e', { permission: 'project.edit', effect: 'deny' }));
    assert.equal(ctx.size, 2, 'o mesmo id substitui');
    assert.deepEqual(engine.checkMany(ctx, requests.slice(0, 2)), [true, false]);
    assert.equal(ctx.removeGrant('v'), true);
    assert.deepEqual(engine.checkMany(ctx, requests.slice(0, 2)), [false, false]);
  });

  await test(`${backend}: pedido ilegível derruba o lote inteiro, sem virar false`, async () => {
    const { Engine, Context } = await load({ backend });
    const engine = new Engine(SPEC);
    const ctx = new Context({ grants: [grant('v')], now: NOW });
    assert.throws(() => engine.checkMany(ctx, [requests[0]!, { subject: ana } as never]), code('INVALID_INPUT'));
    assert.throws(() => engine.checkMany(ctx, 'nope' as never), code('INVALID_INPUT'));
    assert.throws(() => engine.check(ctx, { subject: ana, permission: 5, resource: p1 } as never), code('INVALID_INPUT'));
    assert.throws(() => engine.check(ctx, { ...requests[0]!, subject: { ...ana, attrs: { n: Number.NaN } } }), code('INVALID_ARGUMENT'));
    assert.throws(() => engine.checkMany(ctx, [{ ...requests[0]!, resource: { ...p1, attrs: { n: Number.POSITIVE_INFINITY } } }]), code('INVALID_ARGUMENT'));
  });

  await test(`${backend}: checkMany dentro de um callback não reentra no motor`, async () => {
    const { Engine, Context } = await load({ backend });
    const ctx = new Context({ grants: [grant('c', { condition: { op: 'call', func: 'probe', args: [] } as never })], now: NOW });
    const outcomes: string[] = [];
    const engine: InstanceType<typeof Engine> = new Engine(SPEC, {
      conditions: {
        probe: () => {
          for (const attempt of [() => engine.checkMany(ctx, [requests[0]!]), () => engine.explainMany(ctx, [requests[0]!]), () => engine.check(ctx, requests[0]!)]) {
            try {
              attempt();
              outcomes.push('passou');
            } catch (error) {
              outcomes.push((error as BindingError).code);
            }
          }
          return true;
        },
      },
    });
    assert.equal(engine.check(ctx, requests[0]!), true);
    assert.deepEqual(outcomes, ['REENTRANT_CALL', 'REENTRANT_CALL', 'REENTRANT_CALL']);
    assert.deepEqual(engine.checkMany(ctx, [requests[0]!]), [true], 'o motor segue utilizável');
  });
}

if (failures) console.log(`# batch: ${failures} falha(s)`);
