// Smoke test: every example compiles in the three syntaxes and the engine answers every question.
// Run after the build: node --test playground/test/smoke.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { load } from '../dist/engine/browser.js';
import { compileSource, convertSource, rule } from '../engine.js';
import { CASES } from '../cases.js';

const SYNTAXES = ['blocks', 'rules', 'actors'];
const EXPECTED = {
  Documents: ['allow', 'allow', 'deny'],
  Conditions: ['allow', 'deny', 'allow'],
  'Order decides': ['deny'],
};

const wasm = await readFile(new URL('../dist/engine/wasm/themis_bg.wasm', import.meta.url));
const themis = await load({ wasm });
const NOW = Date.UTC(2026, 0, 1);

for (const c of CASES.filter((x) => !x.flaw)) {
  test(`given the ${c.title} case, when compiled in each syntax, then all three give the same policy shape`, () => {
    const shapes = SYNTAXES.map((syn) => {
      const compiled = compileSource(themis, c.text[syn]);
      assert.equal(compiled.ok, true, `${syn}: ${JSON.stringify(compiled.problems)}`);
      return [compiled.permissions, compiled.grants];
    });
    assert.deepEqual(shapes[1], shapes[0]);
    assert.deepEqual(shapes[2], shapes[0]);
  });

  test(`given the ${c.title} case, when each question is asked, then the engine rules as expected`, () => {
    const compiled = compileSource(themis, c.text.rules);
    const verdicts = c.asks.map((ask) => rule(themis, compiled, ask, NOW).verdict);
    assert.deepEqual(verdicts, EXPECTED[c.title]);
  });
}

test('given the case with a typo, when compiled, then every syntax reports a positioned problem', () => {
  const flawed = CASES.find((x) => x.flaw);
  for (const syn of SYNTAXES) {
    const compiled = compileSource(themis, flawed.text[syn]);
    assert.equal(compiled.ok, false, syn);
    const [problem] = compiled.problems;
    assert.ok(problem.line >= 1 && problem.column >= 1 && problem.length >= 1, syn);
  }
});

test('given an empty source, when compiled, then it fails at the first position', () => {
  const compiled = compileSource(themis, '');
  assert.equal(compiled.ok, false);
  assert.deepEqual([compiled.problems[0].line, compiled.problems[0].column], [1, 1]);
});

test('given a source with problems, when converted, then the result is null', () => {
  assert.equal(convertSource(themis, 'not a policy', 'blocks'), null);
});

test('given a subject the source does not declare, when asked, then the page holds the ruling', () => {
  const compiled = compileSource(themis, CASES[0].text.rules);
  const ask = { ...CASES[0].asks[0], subject: 'user:nobody' };
  assert.equal(rule(themis, compiled, ask, NOW).verdict, 'hold');
});
