// Modo de falha, sink em JavaScript, fila de retentativa, redação e âncora da cadeia de auditoria.
// Roda nos dois alvos (N-API e wasm); `run.js` importa este arquivo.
import assert from 'node:assert/strict';
import { load } from '../dist/node.js';
import type { ApplyInput, EngineHooks, Grant, Subject } from '../dist/index.js';

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
    targetKinds: ['project'],
    broadTargets: ['org'],
    permissions: [
      { key: 'project.view', targets: ['project'] },
      { key: 'project.edit', targets: ['project'] },
    ],
  },
};
const T0 = 1_700_000_000_000;
const actor: Subject = { kind: 'user', id: 'root', attrs: { email: 'root@example.com' } };
const grant = (id: string, permission = 'project.view'): Grant => ({
  id,
  subject: { kind: 'any' },
  permission,
  target: { kind: 'project' },
  effect: 'allow',
});
const input = (id: string, audit: ApplyInput['audit'] = { level: 'forensic' }, extra: Partial<ApplyInput> = {}): ApplyInput =>
  ({ actor, current: [], mutation: { add: grant(id) }, audit, now: T0, ...extra }) as ApplyInput;

for (const backend of ['native', 'wasm'] as const) {
  await test(`${backend}: sem sink o audit só é devolvido, e fica written`, async () => {
    const { Engine } = await load({ backend });
    const out = new Engine(SPEC).apply(input('g1'));
    assert.equal(out.ok, true);
    assert.equal(out.auditStatus, 'written');
    assert.equal(typeof out.audit?.hash, 'string');
  });

  await test(`${backend}: sink que lança recusa em closed, e a mudança segue em open`, async () => {
    const { Engine } = await load({ backend });
    let down = true;
    const taken: Array<Record<string, unknown>> = [];
    const hooks: EngineHooks = {
      auditSink: (record) => {
        if (down) throw new Error('log fora do ar');
        taken.push(record);
      },
    };
    const engine = new Engine(SPEC, hooks);

    const refused = engine.apply(input('g1'));
    assert.equal(refused.ok, false);
    assert.equal(refused.violations?.[0]?.invariant, 'audit');
    assert.match(refused.violations?.[0]?.message ?? '', /log fora do ar/);
    assert.equal(engine.auditStats().pending, 0);

    const open = engine.apply(input('g1', { level: 'forensic', failMode: 'open' }));
    assert.equal(open.ok, true, 'open: a mudança segue');
    assert.equal(open.auditStatus, 'pending');
    assert.equal(typeof open.audit?.hash, 'string', 'o registro pendente é devolvido');
    assert.equal(engine.auditStats().pending, 1);
    assert.equal(taken.length, 0);

    const second = engine.apply(input('g2', { level: 'forensic', failMode: 'open', prevHash: open.audit?.hash as string }));
    assert.equal(second.auditStatus, 'pending');

    down = false;
    const stats = engine.flushAudit();
    assert.equal(stats.pending, 0);
    assert.equal(stats.writtenLate, 2);
    assert.deepEqual(
      taken.map((r) => r.object),
      ['g1', 'g2'],
      'a fila esvazia na ordem',
    );
    assert.equal(taken[1]?.prev_hash, taken[0]?.hash, 'a cadeia chega ao sink em ordem');
    const check = engine.apply(input('g3', { level: 'forensic', prevHash: second.audit?.hash as string }));
    assert.equal(check.auditStatus, 'written');
    assert.equal(taken.length, 3);
  });

  await test(`${backend}: precedência do modo: chamada, permissão, padrão`, async () => {
    const { Engine } = await load({ backend });
    const engine = new Engine(SPEC, {
      auditSink: () => {
        throw new Error('fora');
      },
      auditPolicy: { failMode: 'closed', permissions: { 'project.edit': 'open' } },
    });
    const run = (permission: string, failMode?: 'open' | 'closed') =>
      engine.apply({ ...input('g', { level: 'standard', failMode }), mutation: { add: grant('g', permission) } } as never);
    assert.equal(run('project.view').ok, false, 'padrão closed');
    assert.equal(run('project.edit').ok, true, 'a permissão abre');
    assert.equal(run('project.edit', 'closed').ok, false, 'a chamada vence a permissão');
    assert.equal(run('project.view', 'open').ok, true, 'a chamada abre');
  });

  await test(`${backend}: fila cheia descarta, avisa e a cadeia dos gravados segue verificável`, async () => {
    const { Engine, verifyAuditChain } = await load({ backend });
    let down = true;
    const taken: Array<Record<string, unknown>> = [];
    const dropped: Array<Record<string, unknown>> = [];
    const engine = new Engine(SPEC, {
      auditSink: (record) => {
        if (down) throw new Error('fora');
        taken.push(record);
      },
      onAuditDrop: (record) => dropped.push(record),
      auditPolicy: { failMode: 'open', capacity: 1, baseDelayMs: 0 },
    });
    let prev: string | undefined;
    const statuses: Array<string | null | undefined> = [];
    for (const id of ['g1', 'g2', 'g3']) {
      const out = engine.apply(input(id, { level: 'forensic', prevHash: prev }));
      statuses.push(out.auditStatus);
      if (out.auditStatus !== 'dropped') prev = out.audit?.hash as string;
    }
    assert.deepEqual(statuses, ['pending', 'dropped', 'dropped']);
    assert.equal(dropped.length, 2);
    assert.equal(engine.auditStats().dropped, 2);
    down = false;
    engine.flushAudit();
    assert.equal(taken.length, 1);
    assert.deepEqual(verifyAuditChain(taken), { ok: true, head: taken[0]?.hash });
  });

  await test(`${backend}: redação mascara antes de gravar e de calcular o hash`, async () => {
    const { Engine, verifyAuditChain } = await load({ backend });
    const taken: Array<Record<string, unknown>> = [];
    const engine = new Engine(SPEC, {
      auditSink: (record) => {
        taken.push(record);
      },
      auditRedact: (record) => ({ ...record, object: `redigido:${String(record.object)}` }),
    });
    const out = engine.apply(
      input('g1', { level: 'forensic', redact: { keys: ['email', 'ip'], mask: '***' } }, { meta: { ip: '203.0.113.42', reason: 'x' } }),
    );
    assert.equal(out.ok, true);
    const record = taken[0] as { object: string; meta: Record<string, string>; actor_detail: { attrs: Record<string, string> } };
    assert.equal(record.object, 'redigido:g1');
    assert.equal(record.meta.ip, '***');
    assert.equal(record.meta.reason, 'x');
    assert.equal(record.actor_detail.attrs.email, '***');
    assert.doesNotMatch(JSON.stringify(taken), /203\.0\.113\.42|root@example\.com/);
    assert.equal(verifyAuditChain(taken).ok, true, 'o hash cobre a versão redigida');

    const broken = new Engine(SPEC, {
      auditSink: () => undefined,
      auditRedact: () => {
        throw new Error('sem acesso ao cofre');
      },
      auditPolicy: { failMode: 'open' },
    }).apply(input('g1'));
    assert.equal(broken.ok, false, 'redação que falha recusa mesmo em open');
    assert.match(broken.violations?.[0]?.message ?? '', /sem acesso ao cofre/);
  });

  await test(`${backend}: verifyAuditChain com âncora`, async () => {
    const { Engine, verifyAuditChain } = await load({ backend });
    const records: Array<Record<string, unknown>> = [];
    const engine = new Engine(SPEC, { auditSink: (r) => void records.push(r) });
    let prev: string | undefined;
    for (const id of ['g1', 'g2', 'g3']) {
      prev = engine.apply(input(id, { level: 'forensic', prevHash: prev })).audit?.hash as string;
    }
    const head = records[2]?.hash as string;
    assert.deepEqual(verifyAuditChain(records, { head }), { ok: true, head });
    assert.equal(verifyAuditChain(records.slice(0, 2), { head }).ok, false);
    const cut = verifyAuditChain(records.slice(0, 2), { head });
    assert.equal(cut.ok === false && cut.code, 'HEAD_MISMATCH');
    assert.deepEqual(verifyAuditChain(records.slice(1), { start: records[0]?.hash as string, head }), { ok: true, head });
    const foreign = verifyAuditChain(records.slice(1), { start: 'aa' });
    assert.equal(foreign.ok === false && foreign.code, 'ANCHOR_MISMATCH');
    const edited = records.map((r, i) => (i === 1 ? { ...r, object: 'x' } : r));
    const tampered = verifyAuditChain(edited);
    assert.equal(tampered.ok === false && tampered.code, 'TAMPERED');
    assert.equal(tampered.ok === false && tampered.index, 1);
  });

  await test(`${backend}: sink não reentra no motor`, async () => {
    const { Engine } = await load({ backend });
    let code: string | undefined;
    const engine: InstanceType<typeof Engine> = new Engine(SPEC, {
      auditSink: () => {
        try {
          engine.apply(input('inner'));
        } catch (error) {
          code = (error as { code?: string }).code;
        }
      },
    });
    assert.equal(engine.apply(input('g1')).ok, true);
    assert.equal(code, 'REENTRANT_CALL');
  });
}

if (failures) console.log(`# audit: ${failures} falha(s)`);
