// Testes da API 0.4.0 do binding: validade, consultas, governança com `now`, templates e posse
// exclusiva. Roda nos dois alvos (N-API e wasm); `run.mjs` importa este arquivo.
import assert from 'node:assert/strict';
import { load, scopeFromString } from '../node.js';

const NOW = 1_700_000_000_000;
const HOUR = 3_600_000;
let failures = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failures += 1;
    process.exitCode = 1;
    console.log(`not ok - ${name}\n  ${error?.stack ?? error}`);
  }
}
const code = (expected) => (error) => {
  assert.equal(error.code, expected, `code esperado ${expected}, veio ${error.code}: ${error.message}`);
  return true;
};

const SPEC = {
  catalog: {
    targetKinds: ['project', 'document'],
    broadTargets: ['org'],
    permissions: [
      { key: 'project.view', targets: ['project'] },
      { key: 'project.edit', targets: ['project'] },
      { key: 'project.export', targets: ['project'], dependsOn: ['project.view'] },
      { key: 'project.admin', targets: ['project'], nonDelegable: true },
      { key: 'project.root', targets: ['project'], managementOnly: true },
      { key: 'project.system', targets: ['project'], overrideOnly: true },
      { key: 'document.view', targets: ['project', 'document'], impliedBy: ['project.view'] },
      { key: 'exclusive.hold', targets: ['document'] },
      { key: 'exclusive.preempt', targets: ['document'] },
    ],
  },
  roles: [{ role: 'admin', inherits: ['member'] }],
};
const allow = (id, subject, permission, target = { kind: 'project' }, extra = {}) => ({ id, subject, permission, target, effect: 'allow', ...extra });
const role = (id) => ({ kind: 'role', id });
const p1 = scopeFromString('project:p1/org:o1');
const p2 = scopeFromString('project:p2/org:o1');
const doc = scopeFromString('document:d1/project:p1/org:o1');
const user = (id, roles = []) => ({ kind: 'user', id, roles: roles.map((r) => ({ role: r })) });
const ask = (subject, permission, resource) => ({ subject, permission, resource });

for (const backend of ['native', 'wasm']) {
  const { Engine, Context, Exclusive } = await load({ backend });
  const tag = (name) => `${backend}: ${name}`;

  await test(tag('validade: grant futuro, vencido e deny vencido'), () => {
    const engine = new Engine(SPEC);
    const ana = user('ana');
    const view = ask(ana, 'project.view', p1);
    const future = new Context({ grants: [allow('f', { kind: 'user', id: 'ana' }, 'project.view', undefined, { validFrom: NOW + HOUR })] });
    future.setNow(NOW);
    assert.equal(engine.check(future, view), false, 'grant futuro não vale ainda');
    future.setNow(NOW + HOUR);
    assert.equal(engine.check(future, view), true, 'validFrom é inclusivo');

    const expired = new Context({ grants: [allow('e', { kind: 'user', id: 'ana' }, 'project.view', undefined, { validUntil: NOW })] });
    expired.setNow(NOW - 1);
    assert.equal(engine.check(expired, view), true);
    expired.setNow(NOW);
    assert.equal(engine.check(expired, view), false, 'validUntil é exclusivo');
    assert.equal(engine.explain(expired, view).grants[0].verdict.kind, 'outside_window');

    const deny = { ...allow('d', { kind: 'user', id: 'ana' }, 'project.view', undefined, { validUntil: NOW }), effect: 'deny' };
    const open = allow('a', { kind: 'any' }, 'project.view');
    const denied = new Context({ grants: [open, deny] });
    denied.setNow(NOW - 1);
    assert.equal(engine.check(denied, view), false, 'deny dentro da janela vale');
    denied.setNow(NOW);
    assert.equal(engine.check(denied, view), true, 'deny vencido deixa de negar');
  });

  await test(tag('validade: sem now falha fechado, e now inválido é recusado'), () => {
    const engine = new Engine(SPEC);
    const view = ask(user('ana'), 'project.view', p1);
    const windowedAllow = new Context({ grants: [allow('e', { kind: 'any' }, 'project.view', undefined, { validUntil: NOW + HOUR })] });
    assert.equal(engine.check(windowedAllow, view), false, 'allow com janela e sem now é ignorado');
    const windowedDeny = new Context({ grants: [allow('a', { kind: 'any' }, 'project.view'), { ...allow('d', { kind: 'any' }, 'project.view', undefined, { validUntil: NOW }), effect: 'deny' }] });
    assert.equal(engine.check(windowedDeny, view), false, 'deny com janela e sem now vale');
    windowedAllow.setNow(NOW);
    windowedAllow.setNow(null);
    assert.equal(engine.check(windowedAllow, view), false, 'setNow(null) remove o instante');
    assert.throws(() => windowedAllow.setNow(-1), code('INVALID_ARGUMENT'));
    assert.throws(() => windowedAllow.setNow(1.5), code('INVALID_ARGUMENT'));
    assert.throws(() => new Context({ now: 'agora' }), code('INVALID_ARGUMENT'));
    assert.throws(() => engine.validateGrant(allow('w', { kind: 'any' }, 'project.view', undefined, { validFrom: NOW, validUntil: NOW })), code('INVALID_GRANT'));
    assert.equal(new Context({ now: NOW }).size, 0);
  });

  await test(tag('governança com now: janela do ator conta no instante'), () => {
    const engine = new Engine(SPEC);
    const ana = user('ana');
    const mine = allow('a', { kind: 'user', id: 'ana' }, 'project.edit', undefined, { validUntil: NOW });
    const input = (now) => ({
      actor: ana,
      current: [mine],
      mutation: { add: allow('b', { kind: 'user', id: 'bob' }, 'project.edit') },
      invariants: [{ kind: 'no_escalation' }],
      audit: { level: 'standard' },
      now,
    });
    const before = engine.apply(input(NOW - 1));
    assert.equal(before.ok, true, 'o grant do ator ainda vale');
    assert.equal(before.audit.at, NOW - 1, 'a auditoria usa o mesmo instante');
    const after = engine.apply(input(NOW));
    assert.equal(after.ok, false, 'o grant do ator venceu: não pode repassar');
    assert.equal(after.violations[0].invariant, 'no_escalation');
    assert.throws(() => engine.apply(input(-5)), code('INVALID_ARGUMENT'));
    assert.throws(() => engine.apply({ ...input(NOW), mutation: { nope: 1 } }), code('INVALID_INPUT'));
  });

  await test(tag('invariantes do catálogo: depends_on, non_delegable, management_only, override_only'), () => {
    const engine = new Engine(SPEC);
    const ctx = new Context({ grants: [allow('v', role('member'), 'project.view')] });
    const member = user('ana', ['member']);
    assert.equal(engine.decide(ctx, ask(member, 'project.export', p1)).effect, 'deny');
    const withExport = new Context({ grants: [allow('x', role('member'), 'project.export')] });
    assert.equal(engine.decide(withExport, ask(member, 'project.export', p1)).reason.kind, 'missing_prerequisite');

    const root = { kind: 'user', id: 'root' };
    const run = (grant, invariants, extra = {}) => engine.apply({ actor: root, current: [], mutation: { add: grant }, invariants, ...extra });
    const prerequisites = run(allow('x', role('member'), 'project.export'), [{ kind: 'prerequisites' }]);
    assert.equal(prerequisites.ok, false);
    assert.equal(prerequisites.violations[0].invariant, 'prerequisites');

    const nonDelegable = run(allow('n', role('member'), 'project.admin'), [{ kind: 'non_delegable', manager: 'project.edit' }]);
    assert.equal(nonDelegable.ok, false);
    assert.equal(nonDelegable.violations[0].invariant, 'non_delegable');

    const management = run(allow('m', role('member'), 'project.root'), [{ kind: 'management_only', roles: ['owner'] }]);
    assert.equal(management.ok, false);
    assert.equal(management.violations[0].invariant, 'management_only');
    assert.equal(run(allow('m', role('owner'), 'project.root'), [{ kind: 'management_only', roles: ['owner'] }]).ok, true);

    assert.throws(() => engine.validateGrant(allow('o', role('member'), 'project.system')), code('INVALID_GRANT'));
    const overrideOnly = new Context({ grants: [allow('o', role('member'), 'project.system')] });
    assert.equal(engine.check(overrideOnly, ask(member, 'project.system', p1)), false, 'override_only ignora grants');
  });

  await test(tag('proposta de correção de lockout'), () => {
    const engine = new Engine(SPEC);
    const ana = user('ana', ['owner']);
    const zed = user('zed');
    const out = engine.apply({
      actor: { kind: 'user', id: 'root' },
      current: [allow('o', role('owner'), 'project.edit')],
      mutation: { revoke_role: { subject: ana, role: { role: 'owner' } } },
      invariants: [
        {
          kind: 'no_lockout',
          permissions: ['project.edit'],
          members: [ana, zed],
          resource: p1,
          reserve: { adminRole: { role: 'owner' }, subjects: [zed] },
        },
      ],
    });
    assert.equal(out.ok, false);
    assert.equal(out.violations[0].invariant, 'no_lockout');
    assert.deepEqual(out.violations[0].suggestion, { kind: 'assign_role', subjectId: 'zed', role: { role: 'owner' } });
  });

  await test(tag('templates: cópia desconectada, lote aplicado e recusa'), () => {
    const engine = new Engine(SPEC);
    const template = {
      id: 'viewer',
      version: 3,
      grants: [
        { id: 'export', permission: 'project.export', target: { kind: 'project' } },
        { id: 'view', permission: 'project.view', target: { kind: 'project' } },
      ],
    };
    const copy = engine.materialize({ template, subject: { kind: 'user', id: 'bob' }, scope: { kind: 'org', id: 'o1' }, idPrefix: 'bob' });
    assert.equal(copy.templateVersion, 3);
    assert.equal(copy.mutations.length, 2);
    assert.equal(copy.mutations[0].add.id, 'bob:export');
    assert.deepEqual(copy.mutations[0].add.scope, { kind: 'org', id: 'o1' });
    const snapshot = JSON.stringify(copy);
    template.grants.pop();
    assert.equal(JSON.stringify(engine.materialize({ template: { ...template, grants: [...template.grants] }, subject: { kind: 'user', id: 'bob' }, scope: { kind: 'org', id: 'o1' }, idPrefix: 'bob' })).includes('bob:view'), false);
    assert.equal(JSON.stringify(copy), snapshot, 'mudar o template não muda a cópia já feita');
    copy.mutations[0].add.id = 'x';
    assert.equal(template.grants[0].id, 'export', 'mudar a cópia não muda o template');

    const actor = { kind: 'user', id: 'root' };
    const base = { actor, current: [], subject: { kind: 'user', id: 'bob' }, idPrefix: 'bob', invariants: [{ kind: 'prerequisites' }, { kind: 'catalog_conformance' }], audit: { level: 'standard' } };
    const full = { ...template, grants: [...template.grants, { id: 'view', permission: 'project.view', target: { kind: 'project' } }] };
    const applied = engine.applyTemplate({ ...base, template: full });
    assert.equal(applied.ok, true, 'a dependência vai antes de quem depende dela');
    assert.deepEqual(applied.grants.map((g) => g.id), ['bob:view', 'bob:export']);
    assert.equal(applied.audits.length, 2);

    const refused = engine.applyTemplate({ ...base, template: { id: 'bad', version: 1, grants: [{ id: 'x', permission: 'nope', target: { kind: 'project' } }] } });
    assert.equal(refused.ok, false);
    assert.equal(refused.grants, undefined);
    assert.equal(refused.audits.length, 1, 'só a recusa vai à trilha');
    assert.equal(refused.audits[0].outcome, 'rejected');

    assert.throws(() => engine.materialize({ template: 5 }), code('INVALID_INPUT'));
    assert.throws(() => engine.applyTemplate({ ...base, template: full, now: 'x' }), code('INVALID_ARGUMENT'));
  });

  await test(tag('list: forma, expressão, ids e erro'), () => {
    const engine = new Engine(SPEC);
    const ctx = new Context({
      grants: [
        allow('g1', role('member'), 'project.view'),
        allow('g2', { kind: 'user', id: 'ana' }, 'project.edit', { kind: 'project', id: 'p1' }),
      ],
    });
    const ana = user('ana', ['member']);
    const all = engine.list(ctx, ana, 'project.view', 'project', { layout: ['project', 'org'] });
    assert.equal(all.kind, 'project');
    assert.equal(all.permission, 'project.view');
    assert.equal(all.shape.type, 'compound');
    assert.deepEqual(all.expr, { op: 'on_path', selector: { kind: 'project' } });
    assert.equal(all.exact, true);
    assert.equal(all.ids, null, 'sem recursos não há ids');

    const some = engine.list(ctx, ana, 'project.edit', 'project', { layout: ['project', 'org'], resources: [p1, p2] });
    assert.deepEqual(some.shape, { type: 'ids', ids: ['p1'] });
    assert.deepEqual(some.ids, ['p1']);
    assert.equal(some.expr.op, 'anchor_in');

    const nothing = engine.list(ctx, user('zed'), 'project.edit', 'project');
    assert.deepEqual(nothing.shape, { type: 'nothing' });
    assert.deepEqual(nothing.expr, { op: 'false' });

    assert.throws(() => engine.list(ctx, 5, 'project.view', 'project'), code('INVALID_INPUT'));
    assert.throws(() => engine.list(ctx, ana, 'project.view', 'project', { resources: 'p1' }), code('INVALID_INPUT'));
  });

  await test(tag('list: o instante do contexto vale na listagem'), () => {
    const engine = new Engine(SPEC);
    const ctx = new Context({ grants: [allow('t', { kind: 'user', id: 'ana' }, 'project.view', undefined, { validUntil: NOW })] });
    const ana = user('ana');
    ctx.setNow(NOW - 1);
    assert.equal(engine.list(ctx, ana, 'project.view', 'project').shape.type, 'compound');
    ctx.setNow(NOW);
    assert.deepEqual(engine.list(ctx, ana, 'project.view', 'project').shape, { type: 'nothing' });
  });

  await test(tag('consultas reversas: whoCan, whoCanOn, accessOf, checkFor'), () => {
    const engine = new Engine(SPEC);
    const ctx = new Context({
      grants: [allow('g1', role('member'), 'project.view'), allow('g2', { kind: 'user', id: 'ana' }, 'project.edit')],
    });
    const who = engine.whoCan(ctx, 'project.view');
    assert.deepEqual(who, [{ type: 'role', id: 'member' }]);
    assert.deepEqual(engine.whoCan(ctx, 'project.nope'), []);

    const on = engine.whoCanOn(ctx, 'project.edit', p1);
    assert.equal(on.permission, 'project.edit');
    assert.deepEqual(on.entries, [{ subject: { type: 'user', id: 'ana' }, via: { type: 'grant', grantId: 'g2' } }]);

    const access = engine.accessOf(ctx, p1);
    const ana = access.find((p) => p.subject.type === 'user' && p.subject.id === 'ana');
    assert.ok(ana.permissions.includes('project.edit'));

    const checked = engine.checkFor(ctx, { type: 'user', id: 'ana' }, 'project.edit', p1, [user('ana')]);
    assert.equal(checked.allowed, true);
    assert.equal(checked.via.grantId, 'g2');
    assert.equal(checked.explanation.decision.effect, 'allow');
    const denied = engine.checkFor(ctx, { type: 'user', id: 'ana' }, 'project.view', p1, [user('ana')]);
    assert.equal(denied.allowed, false);
    assert.equal(denied.via.type, 'nothing');

    assert.throws(() => engine.checkFor(ctx, { type: 'user', id: 'ghost' }, 'project.edit', p1, []), code('UNKNOWN_SUBJECT'));
    assert.throws(() => engine.checkFor(ctx, { type: 'planet' }, 'project.edit', p1, []), code('INVALID_INPUT'));
    assert.throws(() => engine.whoCanOn(ctx, 'project.edit', 'p1'), code('INVALID_INPUT'));
    assert.throws(() => engine.accessOf(ctx, 7), code('INVALID_INPUT'));
  });

  await test(tag('consultas reversas: QueryLimits fecham em vez de responder parcial'), () => {
    const engine = new Engine(SPEC);
    const grants = ['a', 'b', 'c'].map((id) => allow(`g${id}`, { kind: 'user', id }, 'project.view'));
    const ctx = new Context({ grants, limits: { maxParties: 2 } });
    assert.throws(() => engine.whoCanOn(ctx, 'project.view', p1), code('QUERY_LIMIT_EXCEEDED'));
    assert.throws(() => engine.accessOf(ctx, p1), code('QUERY_LIMIT_EXCEEDED'));
    ctx.setLimits({ maxParties: 10, maxDecisions: 1 });
    assert.throws(() => engine.accessOf(ctx, p1), code('QUERY_LIMIT_EXCEEDED'));
    ctx.setLimits(null);
    assert.equal(engine.whoCanOn(ctx, 'project.view', p1).entries.length, 3);
    assert.throws(() => ctx.setLimits({ maxParties: -1 }), code('INVALID_ARGUMENT'));
    assert.throws(() => ctx.setLimits('muitos'), code('INVALID_INPUT'));
  });

  await test(tag('consultas reversas respeitam o now do contexto'), () => {
    const engine = new Engine(SPEC);
    const ctx = new Context({ grants: [allow('t', { kind: 'user', id: 'ana' }, 'project.view', undefined, { validFrom: NOW + HOUR })], now: NOW });
    assert.deepEqual(engine.whoCan(ctx, 'project.view'), []);
    assert.deepEqual(engine.whoCanOn(ctx, 'project.view', p1).entries, []);
    ctx.setNow(NOW + HOUR);
    assert.equal(engine.whoCan(ctx, 'project.view').length, 1);
  });

  await test(tag('posse exclusiva: prioridade, preempção, prazo e erros'), () => {
    const engine = new Engine(SPEC);
    const ctx = new Context({
      grants: [
        allow('h', role('op'), 'exclusive.hold', { kind: 'document' }),
        allow('hc', role('chief'), 'exclusive.hold', { kind: 'document' }),
        allow('pc', role('chief'), 'exclusive.preempt', { kind: 'document' }),
      ],
    });
    const lock = new Exclusive({ maxTtlMs: 10 * HOUR });
    lock.validate(engine);
    const low = user('low', ['op']);
    const chief = user('chief', ['chief']);
    const outsider = user('out');
    const d1 = { kind: 'document', id: 'd1' };

    const first = lock.acquire(engine, ctx, low, doc, { priority: 1, ttlMs: HOUR }, NOW);
    assert.equal(first.outcome, 'granted');
    assert.equal(first.lease.holder.id, 'low');
    assert.equal(first.lease.expiresAt, NOW + HOUR);

    const same = lock.acquire(engine, ctx, user('low2', ['op']), doc, { priority: 1, ttlMs: HOUR }, NOW + 1);
    assert.equal(same.outcome, 'busy', 'prioridade igual nunca toma');
    assert.equal(same.holder.holder.id, 'low');

    const taken = lock.acquire(engine, ctx, chief, doc, { priority: 9, ttlMs: HOUR }, NOW + 2);
    assert.equal(taken.outcome, 'preempted');
    assert.equal(taken.previous.holder.id, 'low', 'quem perdeu a posse, para avisar');
    assert.equal(lock.holder(d1, NOW + 3).holder.id, 'chief');

    assert.throws(() => lock.acquire(engine, ctx, low, doc, { priority: 99, ttlMs: HOUR }, NOW + 4), code('EXCLUSIVE_DENIED'));
    assert.throws(() => lock.acquire(engine, ctx, outsider, doc, { priority: 1, ttlMs: HOUR }, NOW + 4), code('EXCLUSIVE_DENIED'));
    assert.throws(() => lock.acquire(engine, ctx, chief, doc, { priority: 9, ttlMs: 0 }, NOW + 4), code('EXCLUSIVE_ZERO_TTL'));
    assert.throws(() => lock.acquire(engine, ctx, chief, doc, { priority: 9, ttlMs: 11 * HOUR }, NOW + 4), code('EXCLUSIVE_TTL_TOO_LONG'));
    assert.throws(() => lock.acquire(engine, ctx, { kind: 'user' }, doc, { priority: 9, ttlMs: HOUR }, NOW + 4), code('EXCLUSIVE_ANONYMOUS_SUBJECT'));
    assert.throws(() => lock.acquire(engine, ctx, chief, doc, { priority: 'alta', ttlMs: HOUR }, NOW + 4), code('INVALID_INPUT'));

    assert.throws(() => lock.release(d1, { kind: 'user', id: 'low' }, NOW + 5), code('EXCLUSIVE_NOT_HOLDER'));
    const renewed = lock.renew(engine, ctx, chief, doc, 2 * HOUR, NOW + 6);
    assert.equal(renewed.expiresAt, NOW + 6 + 2 * HOUR);
    assert.throws(() => lock.renew(engine, ctx, chief, doc, 0, NOW + 7), code('EXCLUSIVE_ZERO_TTL'));

    assert.deepEqual(lock.expire(NOW + 7), []);
    const expired = lock.expire(NOW + 7 + 2 * HOUR);
    assert.equal(expired.length, 1);
    assert.equal(lock.holder(d1, NOW + 7 + 2 * HOUR), null);
    assert.throws(() => lock.release(d1, { kind: 'user', id: 'chief' }, NOW + 8 + 2 * HOUR), code('EXCLUSIVE_NOT_HELD'));

    const again = lock.acquire(engine, ctx, low, doc, { priority: 1, ttlMs: HOUR }, NOW + 10 * HOUR);
    assert.equal(again.outcome, 'granted');
    assert.equal(lock.release(d1, { kind: 'user', id: 'low' }, NOW + 10 * HOUR + 1).holder.id, 'low');
  });

  await test(tag('posse exclusiva: catálogo sem as permissões e nomes configuráveis'), () => {
    const bare = new Engine({ catalog: { targetKinds: ['document'], permissions: [{ key: 'doc.edit', targets: ['document'] }] } });
    assert.throws(() => new Exclusive().validate(bare), code('EXCLUSIVE_UNKNOWN_PERMISSION'));
    new Exclusive({ permissions: { hold: 'doc.edit', preempt: 'doc.edit' } }).validate(bare);
    assert.throws(() => new Exclusive({ ttl: 5 }), code('INVALID_INPUT'));
  });

  await test(tag('now inválido: recusado com INVALID_ARGUMENT em todas as entradas'), () => {
    const engine = new Engine(SPEC);
    const base = { actor: user('root'), current: [], mutation: { add: allow('b', { kind: 'any' }, 'project.view') }, invariants: [], audit: { level: 'standard' } };
    const tpl = { template: { id: 't', version: 1, grants: [{ id: 'v', permission: 'project.view', target: { kind: 'project' } }] }, subject: { kind: 'user', id: 'bob' }, idPrefix: 'bob', actor: user('root'), current: [], invariants: [], audit: { level: 'standard' } };
    const lock = new Exclusive();
    const ctx = new Context();
    const bad = [Number.NaN, Infinity, -Infinity, '', '0', [], false, 0.5, -1];
    for (const now of bad) {
      const label = `now=${String(now)}`;
      assert.throws(() => ctx.setNow(now), code('INVALID_ARGUMENT'), `setNow ${label}`);
      assert.throws(() => new Context({ now }), code('INVALID_ARGUMENT'), `Context ${label}`);
      assert.throws(() => engine.apply({ ...base, now }), code('INVALID_ARGUMENT'), `apply ${label}`);
      assert.throws(() => engine.applyTemplate({ ...tpl, now }), code('INVALID_ARGUMENT'), `applyTemplate ${label}`);
      assert.throws(() => lock.holder({ kind: 'document', id: 'd1' }, now), code('INVALID_ARGUMENT'), `holder ${label}`);
      assert.throws(() => lock.expire(now), code('INVALID_ARGUMENT'), `expire ${label}`);
    }
    assert.equal(ctx.setNow(0), undefined, 'zero é um instante válido');
  });

  await test(tag('now inválido em setNow não limpa o instante guardado'), () => {
    const engine = new Engine(SPEC);
    const ctx = new Context({ grants: [allow('e', { kind: 'any' }, 'project.view', undefined, { validUntil: NOW + HOUR })] });
    ctx.setNow(NOW);
    assert.throws(() => ctx.setNow(Number.NaN), code('INVALID_ARGUMENT'));
    assert.equal(engine.check(ctx, ask(user('ana'), 'project.view', p1)), true, 'o instante anterior segue valendo');
  });

  await test(tag('tipo errado em parâmetro tipado: INVALID_ARGUMENT'), () => {
    const engine = new Engine(SPEC);
    const ctx = new Context();
    assert.throws(() => ctx.removeGrant(5), code('INVALID_ARGUMENT'));
    assert.throws(() => engine.whoCan(ctx, 5), code('INVALID_ARGUMENT'));
    assert.throws(() => new Exclusive().acquire(engine, ctx, user('a'), doc, { priority: 1, ttlMs: '5' }, NOW), code('INVALID_ARGUMENT'));
    assert.throws(() => new Exclusive().renew(engine, ctx, user('a'), doc, '5', NOW), code('INVALID_ARGUMENT'));
  });

  await test(tag('now por chamada vence o do contexto'), () => {
    const engine = new Engine(SPEC);
    const view = ask(user('ana'), 'project.view', p1);
    const ctx = new Context({ grants: [allow('e', { kind: 'any' }, 'project.view', undefined, { validUntil: NOW })] });
    ctx.setNow(NOW - 1);
    assert.equal(engine.check(ctx, view), true);
    assert.equal(engine.check(ctx, view, NOW), false, 'o now da chamada decide');
    assert.equal(engine.decide(ctx, view, NOW).effect, 'deny');
    assert.equal(engine.whoCan(ctx, 'project.view', NOW).length, 0);
    assert.throws(() => engine.check(ctx, view, Number.NaN), code('INVALID_ARGUMENT'));
  });

  await test(tag('posse exclusiva: renew de quem perdeu a permissão'), () => {
    const engine = new Engine(SPEC);
    const ctx = new Context({ grants: [allow('h', role('op'), 'exclusive.hold', { kind: 'document' }, { validUntil: NOW + 100 })] });
    const lock = new Exclusive();
    const low = user('low', ['op']);
    lock.acquire(engine, ctx, low, doc, { priority: 1, ttlMs: HOUR }, NOW);
    assert.equal(lock.renew(engine, ctx, low, doc, HOUR, NOW + 50).expiresAt, NOW + 50 + HOUR);
    assert.throws(() => lock.renew(engine, ctx, low, doc, HOUR, NOW + 100), code('EXCLUSIVE_DENIED'));
    assert.equal(lock.holder({ kind: 'document', id: 'd1' }, NOW + 60).expiresAt, NOW + 50 + HOUR, 'a posse não mudou');
  });
}

if (failures) console.log(`# binding040: ${failures} falha(s)`);
