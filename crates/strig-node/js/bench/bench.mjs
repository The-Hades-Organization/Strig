// Benchmarks of the JS binding: decide, check, batches, conditions and relations, list, apply with governance and audit.
// Run from crates/strig-node/js after the native and wasm builds and `npm run build:ts`:
//   node bench/bench.mjs [--backend native|wasm|both]
//   bun bench/bench.mjs [--backend native|wasm|both]
// Numbers and method: docs/benchmarks.md.
import { load } from '../dist/node.js';

const argIndex = process.argv.indexOf('--backend');
const which = argIndex > 0 ? process.argv[argIndex + 1] : 'both';
const backends = which === 'both' ? ['native', 'wasm'] : [which];

const NOW = 1_704_110_400_000; // 2024-01-01 12:00 UTC, a Monday.
const ROWS = 10_000;
const PROJECTS = 50;
const NOISE = 1_000;
const WARMUP_MS = 300;
const SAMPLE_MS = 500;
const SAMPLES = 7;
const BATCH = 100;

const spec = {
  catalog: {
    targetKinds: ['document', 'project'],
    broadTargets: ['org'],
    permissions: [
      { key: 'document.view', targets: ['project', 'document'] },
      { key: 'document.edit', targets: ['project', 'document'] },
    ],
  },
  relations: [{ kind: 'project', relation: 'editor', rewrite: { rewrite: 'this' } }],
};

const org = { kind: 'org', id: 'o1' };
const member = { kind: 'user', id: 'u1', roles: [{ role: 'member', scope: org }] };
const root = { kind: 'user', id: 'root' };
const document = (n) => ({
  path: [
    { kind: 'document', id: `d${n}` },
    { kind: 'project', id: `p${n % PROJECTS}` },
    org,
  ],
  attrs: n % 3 === 0 ? { status: 'draft' } : {},
});

const role = (id) => ({ kind: 'role', id });
const simpleGrants = [
  { id: 'view', subject: role('member'), permission: 'document.view', target: org, effect: 'allow', scope: org },
];
const richGrants = [
  ...simpleGrants,
  {
    id: 'edit-drafts',
    subject: role('member'),
    permission: 'document.edit',
    target: org,
    effect: 'allow',
    scope: org,
    condition: {
      op: 'all',
      of: [
        { op: 'eq', left: { attr: 'resource.status' }, right: 'draft' },
        { op: 'time_between', from: '09:00', until: '18:00' },
      ],
    },
  },
  { id: 'editors', subject: { kind: 'relation', relation: 'editor' }, permission: 'document.edit', target: { kind: 'project' }, effect: 'allow' },
  ...Array.from({ length: NOISE }, (_, n) => ({
    id: `noise-${n}`,
    subject: role('member'),
    permission: 'document.view',
    target: { kind: 'project', id: `q${n}` },
    effect: 'allow',
  })),
];
const tuples = Array.from({ length: PROJECTS }, (_, n) => ({
  object: { kind: 'project', id: `p${n}` },
  relation: 'editor',
  subject: { object: { kind: 'user', id: 'u1' } },
}));

function measure(fn) {
  for (const start = performance.now(); performance.now() - start < WARMUP_MS; ) fn();
  const perOp = [];
  for (let s = 0; s < SAMPLES; s += 1) {
    let runs = 0;
    const start = performance.now();
    while (performance.now() - start < SAMPLE_MS) {
      fn();
      runs += 1;
    }
    perOp.push(((performance.now() - start) * 1e6) / runs);
  }
  perOp.sort((a, b) => a - b);
  return { median: perOp[SAMPLES >> 1], min: perOp[0], max: perOp[SAMPLES - 1] };
}

function format(ns) {
  if (ns >= 1e6) return `${(ns / 1e6).toFixed(2)} ms`;
  if (ns >= 1e3) return `${(ns / 1e3).toFixed(2)} µs`;
  return `${ns.toFixed(0)} ns`;
}

const runtime = typeof Bun !== 'undefined' ? `bun ${Bun.version}` : `node ${process.versions.node}`;
console.log(`runtime: ${runtime}`);

for (const backend of backends) {
  const { Engine, Context } = await load({ backend });
  const rows = [];
  // `per` divides a batched call into the cost of one decision, which is what the table shows.
  const bench = (name, fn, per = 1) => {
    const r = measure(fn);
    rows.push([per > 1 ? `${name} (per decision)` : name, { median: r.median / per, min: r.min / per, max: r.max / per }]);
  };

  const engine = new Engine(spec);
  const simple = new Context({ grants: simpleGrants, now: NOW });
  const viewRequest = { subject: member, permission: 'document.view', resource: document(1) };
  bench('decide/simple', () => engine.decide(simple, viewRequest));
  bench('check/simple', () => engine.check(simple, viewRequest));
  bench('explain/simple', () => engine.explain(simple, viewRequest));
  const batch = Array.from({ length: BATCH }, () => viewRequest);
  bench(`checkMany/simple_x${BATCH}`, () => engine.checkMany(simple, batch), BATCH);
  bench(`explainMany/simple_x${BATCH}`, () => engine.explainMany(simple, batch), BATCH);

  const rich = new Context({ grants: richGrants, tuples, now: NOW });
  const editRequest = { subject: member, permission: 'document.edit', resource: document(3) };
  bench('decide/conditions_and_relations', () => engine.decide(rich, editRequest));
  bench('check/conditions_and_relations', () => engine.check(rich, editRequest));

  const docs = Array.from({ length: ROWS }, (_, n) => document(n));
  const layout = ['document', 'project', 'org'];
  bench('list/plan', () => engine.list(rich, member, 'document.edit', 'document', { layout }));
  bench('list/resolve_10k_rows', () => engine.list(rich, member, 'document.edit', 'document', { layout, resources: docs }));

  const change = (audit) => ({
    actor: root,
    current: simpleGrants,
    mutation: { add: { id: 'new', subject: { kind: 'any' }, permission: 'document.edit', target: { kind: 'document' }, effect: 'allow' } },
    invariants: [{ kind: 'catalog_conformance' }, { kind: 'no_self_management' }],
    now: NOW,
    ...(audit ? { audit: { level: 'standard' } } : {}),
  });
  const plain = change(false);
  bench('apply/governance', () => engine.apply(plain));
  const audited = change(true);
  bench('apply/governance_with_audit', () => engine.apply(audited));
  const sunk = new Engine(spec, { auditSink: () => undefined });
  bench('apply/governance_with_audit_sink', () => sunk.apply(audited));

  console.log(`\nbackend: ${backend}`);
  console.log(`${'case'.padEnd(36)} ${'median'.padStart(11)} ${'min'.padStart(11)} ${'max'.padStart(11)}`);
  for (const [name, r] of rows) {
    console.log(`${name.padEnd(36)} ${format(r.median).padStart(11)} ${format(r.min).padStart(11)} ${format(r.max).padStart(11)}`);
  }
}
