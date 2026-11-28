// Tests of the inspector logic (inspector-core.ts) against the real engine, on the same example the
// `strig-inspect` desktop tool ships. Run after the build: npm test in playground/
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import type * as Browser from '../../crates/strig-node/js/dist/browser.js';
import { Session, matrixChanges, parseScenario, parseTrail, replayRecord, verifyTrail } from '../inspector-core.js';
import type { Scenario } from '../inspector-core.js';

const { load } = (await import(new URL('../../dist/engine/browser.js', import.meta.url).href)) as typeof Browser;
const wasm = await readFile(new URL('../../dist/wasm/strig_bg.wasm', import.meta.url));
const strig = await load({ wasm });
const NOW = Date.UTC(2026, 0, 1);

const EXAMPLES = new URL('../../../crates/strig-inspect/examples/', import.meta.url);
const scenarioText = await readFile(new URL('scenario.json', EXAMPLES), 'utf8');
const trailText = await readFile(new URL('audit.jsonl', EXAMPLES), 'utf8');

function scenario(): Scenario {
  const parsed = parseScenario(scenarioText);
  assert.ok(parsed.ok);
  return parsed.value;
}

function session(): Session {
  const opened = Session.open(strig, scenario(), NOW);
  assert.ok(opened.ok);
  return opened.value;
}

const cell = (session: Session, resource: string, permission: string, subject: string) => {
  const matrix = session.matrix(resource);
  return matrix.cells[matrix.permissions.indexOf(permission)]?.[matrix.subjects.indexOf(subject)];
};

test('given the shipped example, when parsed, then every part of the scenario is there', () => {
  const s = scenario();
  assert.equal(s.grants.length, 5);
  assert.deepEqual(Object.keys(s.subjects), ['ana', 'ben', 'cara', 'visitor']);
  assert.deepEqual(Object.keys(s.resources), ['roadmap', 'invoice-7', 'secret']);
  assert.equal(s.env.hour, 10);
});

test('given a scenario with an unknown field, when parsed, then it is refused by name', () => {
  const parsed = parseScenario('{"spec": {}, "grant": []}');
  assert.ok(!parsed.ok);
  assert.match(parsed.message, /Unknown field `grant`/);
});

test('given a scenario without spec, or with broken JSON, when parsed, then the message says what is wrong', () => {
  const missing = parseScenario('{"grants": []}');
  assert.ok(!missing.ok);
  assert.match(missing.message, /`spec`/);
  const broken = parseScenario('{\n  "spec": {,\n}');
  assert.ok(!broken.ok);
  assert.match(broken.message, /line 2/);
});

test('given a resource without a path, when parsed, then it is refused', () => {
  const parsed = parseScenario('{"spec": {}, "resources": {"r": {}}}');
  assert.ok(!parsed.ok);
  assert.match(parsed.message, /resource `r`/);
});

test('given a spec the engine refuses, when the session opens, then the engine message comes back', () => {
  const opened = Session.open(strig, { ...scenario(), spec: { catalog: { permissions: 'nope' } } }, NOW);
  assert.ok(!opened.ok);
  assert.match(opened.message, /refused/);
});

test('given the example, when ben asks for document.view on secret, then the deny grant decides', () => {
  const s = session();
  const { now, before, changed } = s.compare(s.scenario.subjects.ben!, 'document.view', s.scenario.resources.secret!);
  assert.equal(now.decision.effect, 'deny');
  assert.deepEqual(now.decision.reason.kind === 'grant' ? now.decision.reason.grantId : null, 'no-secret');
  assert.equal(before, null);
  assert.equal(changed, false);
});

test('given the example, when the matrix is built, then each cell equals the engine decision', () => {
  const s = session();
  const matrix = s.matrix('roadmap');
  assert.equal(matrix.permissions.length, 6);
  assert.equal(matrix.subjects.length, 4);
  matrix.permissions.forEach((permission, p) =>
    matrix.subjects.forEach((name, i) => {
      const subject = s.scenario.subjects[name]!;
      const decided = s.engine.check(new strig.Context({ grants: s.scenario.grants, tuples: s.scenario.tuples, env: s.scenario.env, now: NOW }), { subject, permission, resource: s.scenario.resources.roadmap! });
      assert.equal(matrix.cells[p]![i], decided ? 'allow' : 'deny', `${permission} for ${name}`);
    }),
  );
  assert.deepEqual(matrixChanges(matrix), []);
});

test('given the owner override, when the matrix is built, then ana is allowed all but delete on roadmap', () => {
  const s = session();
  assert.equal(cell(s, 'roadmap', 'project.edit', 'ana'), 'allow');
  assert.equal(cell(s, 'roadmap', 'project.delete', 'ana'), 'deny');
});

test('given a subject with no role, when the matrix is built, then every cell is a deny', () => {
  const s = session();
  const matrix = s.matrix('secret');
  const visitor = matrix.subjects.indexOf('visitor');
  assert.ok(matrix.cells.every((row) => row[visitor] === 'deny'));
});

test('given a grant switched off, when the matrix is built, then only the cells it decided turn over', () => {
  const s = session();
  s.toggle('no-secret');
  assert.ok(s.isSimulating());
  const changes = matrixChanges(s.matrix('secret'));
  assert.deepEqual(changes.find((c) => c.permission === 'document.view' && c.subject === 'ben'), { permission: 'document.view', subject: 'ben', before: 'deny', after: 'allow' });
  assert.ok(!changes.some((c) => c.subject === 'visitor'));
  assert.ok(changes.every((c) => c.before !== c.after));
  s.toggle('no-secret');
  assert.ok(!s.isSimulating());
  assert.deepEqual(matrixChanges(s.matrix('secret')), []);
});

test('given a grant added to the simulation, when compared, then the original decision comes beside the new one', () => {
  const s = session();
  const grant = { id: 'sim-delete', subject: { kind: 'user' as const, id: 'ben' }, permission: 'project.delete', target: { kind: 'project' }, effect: 'allow' as const };
  const added = s.add(grant);
  assert.ok(added.ok);
  const { now, before, changed } = s.compare(s.scenario.subjects.ben!, 'project.delete', s.scenario.resources.roadmap!);
  assert.equal(now.decision.effect, 'allow');
  assert.equal(before?.decision.effect, 'deny');
  assert.ok(changed);
  s.removeAdded('sim-delete');
  assert.ok(!s.isSimulating());
});

test('given an invalid or repeated grant, when added, then the simulation stays as it was', () => {
  const s = session();
  const base = { subject: { kind: 'any' as const }, target: { kind: 'project' }, effect: 'allow' as const };
  const unknown = s.add({ ...base, id: 'sim-x', permission: 'project.fly' });
  assert.ok(!unknown.ok);
  const repeated = s.add({ ...base, id: 'no-secret', permission: 'project.view' });
  assert.ok(!repeated.ok);
  assert.match(repeated.message, /already exists/);
  const badId = s.add({ ...base, id: 'has space', permission: 'project.view' });
  assert.ok(!badId.ok);
  assert.ok(!s.isSimulating());
});

test('given a simulation, when reset, then the original grants are back', () => {
  const s = session();
  s.toggle('members-view');
  s.reset();
  assert.equal(s.activeGrants().length, s.scenario.grants.length);
});

test('given the shipped trail, when parsed and verified, then the forensic chain is intact', () => {
  const trail = parseTrail(trailText);
  assert.deepEqual(trail.problems, []);
  assert.equal(trail.records.length, 6);
  const status = verifyTrail(strig, trail);
  assert.equal(status.kind, 'intact');
  assert.equal(status.kind === 'intact' ? status.records : 0, 6);
});

test('given a tampered record, when verified, then the chain is broken at that line', () => {
  const trail = parseTrail(trailText);
  trail.records[2] = { ...trail.records[2], outcome: 'allowed' };
  const status = verifyTrail(strig, trail);
  assert.equal(status.kind, 'broken');
  assert.equal(status.kind === 'broken' ? status.line : null, 3);
});

test('given a trail without forensic records, when verified, then there is no chain to check', () => {
  const trail = parseTrail(trailText);
  trail.records = trail.records.map((r) => ({ ...r, level: 'detailed' }));
  assert.equal(verifyTrail(strig, trail).kind, 'absent');
});

test('given a bad line in a trail, when parsed, then the line is reported and the others are kept', () => {
  const [first = ''] = trailText.split('\n');
  const trail = parseTrail(`${first}\nnot json\n\n[1]\n`);
  assert.equal(trail.records.length, 1);
  assert.deepEqual(trail.problems.map((p) => p.line), [2, 4]);
});

test('given the policy that wrote the trail, when every decision is replayed, then none changed', () => {
  const s = session();
  const results = parseTrail(trailText).records.map((record) => replayRecord(s, record));
  assert.ok(results.every((r) => r.kind === 'replayed' && !r.changed));
});

test('given a grant removed from the policy, when the trail is replayed, then the decisions it made are marked', () => {
  const s = session();
  s.toggle('no-secret');
  const trail = parseTrail(trailText);
  const changed = trail.records.map((record) => replayRecord(s, record)).filter((r) => r.kind === 'replayed' && r.changed);
  assert.equal(changed.length, 1);
  const only = trail.records.find((_, i) => replayRecord(s, trail.records[i]!).kind === 'replayed' && (replayRecord(s, trail.records[i]!) as { changed: boolean }).changed);
  assert.equal((only?.decision as { permission: string }).permission, 'document.view');
});

test('given a minimal record, when replayed, then it is skipped with the reason', () => {
  const s = session();
  const replay = replayRecord(s, { at: 1, level: 'minimal', actor: 'ana', action: 'decision', object: 'x', outcome: 'allowed' });
  assert.equal(replay.kind, 'skipped');
  const grantChange = replayRecord(s, { action: 'grant_created' });
  assert.equal(grantChange.kind, 'skipped');
});
