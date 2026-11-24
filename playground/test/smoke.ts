// Smoke test: every example compiles in the three syntaxes and the engine answers every question.
// Run after the build: node --test playground/dist-node/test/smoke.js (npm test in playground/)
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import type * as Browser from '../../crates/strig-node/js/dist/browser.js';
import { compileSource, convertSource, rule } from '../engine.js';
import { CASES } from '../cases.js';

const SYNTAXES = ['blocks', 'rules', 'actors'] as const;
const EXPECTED: Record<string, string[]> = {
  Documents: ['allow', 'allow', 'deny'],
  Conditions: ['allow', 'deny', 'allow'],
  'Order decides': ['deny'],
};

// Compiled to dist-node/test/, so the page build sits two levels up.
const { load } = (await import(new URL('../../dist/engine/browser.js', import.meta.url).href)) as typeof Browser;
const wasm = await readFile(new URL('../../dist/wasm/strig_bg.wasm', import.meta.url));
const strig = await load({ wasm });
const NOW = Date.UTC(2026, 0, 1);

for (const c of CASES.filter((x) => !x.flaw)) {
  test(`given the ${c.title} case, when compiled in each syntax, then all three give the same policy shape`, () => {
    const shapes = SYNTAXES.map((syn) => {
      const compiled = compileSource(strig, c.text[syn]);
      assert.ok(compiled.ok, `${syn}: ${JSON.stringify(compiled.ok ? [] : compiled.problems)}`);
      return [compiled.permissions, compiled.grants];
    });
    assert.deepEqual(shapes[1], shapes[0]);
    assert.deepEqual(shapes[2], shapes[0]);
  });

  test(`given the ${c.title} case, when each question is asked, then the engine rules as expected`, () => {
    const compiled = compileSource(strig, c.text.rules);
    const verdicts = c.asks.map((ask) => rule(strig, compiled, ask, NOW).verdict);
    assert.deepEqual(verdicts, EXPECTED[c.title]);
  });
}

test('given the case with a typo, when compiled, then every syntax reports a positioned problem', () => {
  const flawed = CASES.find((x) => x.flaw);
  assert.ok(flawed);
  for (const syn of SYNTAXES) {
    const compiled = compileSource(strig, flawed.text[syn]);
    assert.ok(!compiled.ok, syn);
    const [problem] = compiled.problems;
    assert.ok(problem, syn);
    assert.ok(problem.line !== null && problem.line >= 1 && problem.column !== null && problem.column >= 1 && problem.length >= 1, syn);
  }
});

test('given an empty source, when compiled, then it fails at the first position', () => {
  const compiled = compileSource(strig, '');
  assert.ok(!compiled.ok);
  assert.deepEqual([compiled.problems[0]?.line, compiled.problems[0]?.column], [1, 1]);
});

test('given a source with problems, when converted, then the result is null', () => {
  assert.equal(convertSource(strig, 'not a policy', 'blocks'), null);
});

test('given a subject the source does not declare, when asked, then the page holds the ruling', () => {
  const compiled = compileSource(strig, CASES[0]!.text.rules);
  const first = CASES[0];
  assert.ok(first?.asks[0]);
  const ask = { ...first.asks[0], subject: 'user:nobody' };
  assert.equal(rule(strig, compiled, ask, NOW).verdict, 'hold');
});
