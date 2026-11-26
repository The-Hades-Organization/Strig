// Callbacks JavaScript síncronos no motor: função da condição `call`, override próprio e invariante
// próprio. Roda nos dois alvos (N-API e wasm); `run.js` importa este arquivo.
import assert from 'node:assert/strict';
import { load, scopeFromString } from '../dist/node.js';
import type { ApplyInput, BindingError, EngineHooks, Grant, Subject } from '../dist/index.js';

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
const p1 = scopeFromString('project:p1/org:o1');
const ana: Subject = { kind: 'user', id: 'ana', attrs: { dept: 'eng' } };
const allow = (id: string, extra: Partial<Grant> = {}): Grant => ({
  id,
  subject: { kind: 'any' },
  permission: 'project.view',
  target: { kind: 'project' },
  effect: 'allow',
  ...extra,
});
const callGrant = (func: string, args: unknown[] = []): Grant =>
  allow('c', { condition: { op: 'call', func, args } as never });
const view = { subject: ana, permission: 'project.view', resource: p1 };

for (const backend of ['native', 'wasm'] as const) {
  await test(`${backend}: função da condição call decide e um throw não libera`, async () => {
    const { Engine, Context } = await load({ backend });
    const seen: unknown[][] = [];
    const engine = new Engine(SPEC, {
      conditions: {
        same: (args) => {
          seen.push(args);
          if (args[0] === 'boom') throw new Error('falhou');
          return args[0] === args[1];
        },
        notBool: () => 'sim' as never,
      },
    });
    const ctx = (func: string, args: unknown[]) => new Context({ grants: [callGrant(func, args)] });
    assert.equal(engine.check(ctx('same', ['eng', 'eng']), view), true);
    assert.equal(engine.check(ctx('same', ['eng', 'ops']), view), false);
    assert.deepEqual(seen[0], ['eng', 'eng']);
    const attrs = new Context({ grants: [callGrant('same', [{ attr: 'subject.dept' }, 'eng'])] });
    assert.equal(engine.check(attrs, view), true, 'os operandos chegam já resolvidos');

    const thrown = ctx('same', ['boom', 'x']);
    assert.equal(engine.check(thrown, view), false);
    const trace = JSON.stringify(engine.explain(thrown, view));
    assert.match(trace, /falhou/, 'a mensagem do erro aparece no rastro');
    assert.equal(engine.check(ctx('notBool', []), view), false);

    const denyOnError = new Context({
      grants: [allow('a'), { ...callGrant('same', ['boom', 'x']), id: 'd', effect: 'deny' }],
    });
    assert.equal(engine.check(denyOnError, view), false, 'deny com condição em erro ainda nega');
  });

  await test(`${backend}: override próprio aparece no rastro, respeita except e um throw nega`, async () => {
    const { Engine, Context } = await load({ backend });
    const requests: unknown[] = [];
    const engine = new Engine(SPEC, {
      overrides: [
        {
          name: 'frozen',
          except: ['project.edit'],
          evaluate: (request) => {
            requests.push(request);
            if (request.subject.id === 'root') return 'allowed';
            if (request.subject.id === 'banned') return 'denied';
            if (request.subject.id === 'bad') throw new Error('indisponível');
            return undefined;
          },
        },
      ],
    });
    const empty = new Context();
    const as = (id: string, permission = 'project.view') => ({ subject: { kind: 'user' as const, id }, permission, resource: p1 });
    assert.equal(engine.check(empty, as('root')), true);
    assert.equal(engine.check(empty, as('banned')), false);
    assert.equal(engine.check(empty, as('bad')), false);
    assert.equal(engine.check(new Context({ grants: [allow('g')] }), as('plain')), true, 'abster deixa os grants decidirem');
    assert.equal(engine.check(empty, as('root', 'project.edit')), false, 'except: nem é consultado');

    const reason = engine.decide(empty, as('banned')).reason;
    assert.deepEqual(reason, { kind: 'override', name: 'frozen' });
    const steps = engine.explain(empty, as('root')).overrides;
    assert.deepEqual(steps, [{ name: 'frozen', outcome: 'allowed' }]);
    const skipped = engine.explain(empty, as('root', 'project.edit')).overrides;
    assert.equal(skipped[0]?.outcome, 'excepted');
    assert.equal((requests[0] as { permission: string }).permission, 'project.view');
  });

  await test(`${backend}: invariante próprio recusa na governança e audita`, async () => {
    const { Engine } = await load({ backend });
    const globalRank: Record<string, number> = { viewer: 1, editor: 2, owner: 3 };
    const inUse = new Set(['editor']);
    const hooks: EngineHooks = {
      invariants: {
        // O papel por ambiente nunca excede o global do mesmo usuário.
        env_role_within_global: ({ mutation }) => {
          if (!('assign_role' in mutation)) return;
          const { subject, role } = mutation.assign_role;
          if (role.scope?.kind !== 'environment') return;
          const global = Math.max(0, ...(subject.roles ?? []).filter((r) => !r.scope).map((r) => globalRank[r.role] ?? 0));
          if ((globalRank[role.role] ?? 0) <= global) return;
          return {
            message: `o papel ${role.role} no ambiente excede o global (${global})`,
            suggestion: { assign_role: { subject, role: { role: 'viewer', scope: role.scope } } },
          };
        },
        // Um papel em uso não se apaga.
        role_in_use: ({ mutation, before }) => {
          if (!('remove' in mutation)) return;
          const grant = before.find((g) => g.id === mutation.remove.id);
          if (grant?.subject.kind === 'role' && inUse.has(grant.subject.id)) return `o papel ${grant.subject.id} está em uso`;
        },
        boom: () => {
          throw new Error('cadastro fora do ar');
        },
      },
    };
    const engine = new Engine(SPEC, hooks);
    const actor: Subject = { kind: 'user', id: 'root' };
    const base = (mutation: ApplyInput['mutation'], names: string[]): ApplyInput => ({
      actor,
      current: [allow('r', { subject: { kind: 'role', id: 'editor' } })],
      mutation,
      invariants: [...names.map((name) => ({ kind: 'custom' as const, name }))],
      audit: { level: 'forensic' },
      now: 1_700_000_000_000,
    });

    const zed: Subject = { kind: 'user', id: 'zed', roles: [{ role: 'viewer' }] };
    const env = { kind: 'environment', id: 'prod' };
    const over = engine.apply(base({ assign_role: { subject: zed, role: { role: 'owner', scope: env } } }, ['env_role_within_global']));
    assert.equal(over.ok, false);
    assert.equal(over.violations?.[0]?.invariant, 'env_role_within_global');
    assert.match(over.violations?.[0]?.message ?? '', /excede o global/);
    assert.equal((over.audit as { outcome: string }).outcome, 'rejected', 'a auditoria registra a recusa como a dos nativos');
    assert.deepEqual(over.violations?.[0]?.suggestion, { kind: 'assign_role', subjectId: 'zed', role: { role: 'viewer', scope: env } });

    const within = engine.apply(base({ assign_role: { subject: zed, role: { role: 'viewer', scope: env } } }, ['env_role_within_global']));
    assert.equal(within.ok, true);

    const used = engine.apply(base({ remove: { id: 'r' } }, ['role_in_use']));
    assert.equal(used.ok, false);
    assert.equal(used.violations?.[0]?.message, 'o papel editor está em uso');
    inUse.delete('editor');
    assert.equal(engine.apply(base({ remove: { id: 'r' } }, ['role_in_use'])).ok, true);

    const thrown = engine.apply(base({ remove: { id: 'r' } }, ['boom']));
    assert.equal(thrown.ok, false);
    assert.equal(thrown.violations?.[0]?.invariant, 'boom');
    assert.match(thrown.violations?.[0]?.message ?? '', /cadastro fora do ar/);

    const template = engine.applyTemplate({
      template: { id: 't', version: 1, grants: [] } as never,
      subject: { kind: 'any' },
      scope: { kind: 'project' },
      idPrefix: 'x',
      actor,
      current: [],
      invariants: [{ kind: 'custom', name: 'boom' }],
      now: 1_700_000_000_000,
    } as never);
    assert.equal(template.ok, true, 'um lote vazio não aciona a invariante');

    assert.throws(
      () => engine.apply(base({ remove: { id: 'r' } }, ['nao_existe'])),
      code('UNKNOWN_INVARIANT'),
    );
  });

  await test(`${backend}: callback não reentra no motor nem muda o contexto`, async () => {
    const { Engine, Context } = await load({ backend });
    const ctx = new Context({ grants: [callGrant('probe')] });
    const other = new Context();
    const outcomes: Array<string | undefined> = [];
    let inUse: 'passou' | 'recusou' = 'passou';
    const engine: InstanceType<typeof Engine> = new Engine(SPEC, {
      conditions: {
        probe: () => {
          for (const attempt of [() => engine.check(ctx, view), () => other.addGrant(allow('x')), () => other.setNow(1)]) {
            try {
              attempt();
              outcomes.push('passou');
            } catch (error) {
              outcomes.push((error as BindingError).code);
            }
          }
          try {
            ctx.addGrant(allow('y'));
          } catch {
            inUse = 'recusou';
          }
          return true;
        },
      },
    });
    assert.equal(engine.check(ctx, view), true);
    assert.deepEqual(outcomes, ['REENTRANT_CALL', 'REENTRANT_CALL', 'REENTRANT_CALL']);
    assert.equal(other.size, 0, 'o outro contexto ficou como estava');
    assert.equal(inUse, 'recusou', 'o contexto em uso não aceita mudança no meio da decisão');
    assert.equal(ctx.size, 1);
    ctx.addGrant(allow('depois'));
    assert.equal(ctx.size, 2, 'passada a decisão, o contexto volta a aceitar mudanças');
    assert.equal(engine.check(ctx, view), true, 'o motor segue utilizável');
  });

  await test(`${backend}: hooks malformados são INVALID_ARGUMENT`, async () => {
    const { Engine } = await load({ backend });
    assert.throws(() => new Engine(SPEC, { conditions: { x: 'nope' as never } }), code('INVALID_ARGUMENT'));
    assert.throws(() => new Engine(SPEC, { overrides: [{ name: 'x' } as never] }), code('INVALID_ARGUMENT'));
    assert.throws(() => new Engine(SPEC, 'hooks' as never), code('INVALID_ARGUMENT'));
    assert.doesNotThrow(() => new Engine(SPEC, undefined));
    assert.doesNotThrow(() => new Engine(SPEC, {}));
  });
}

if (failures) console.log(`# hooks: ${failures} falha(s)`);
