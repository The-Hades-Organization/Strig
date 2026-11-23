// A linguagem de políticas no binding, nos dois alvos (N-API e wasm). `run.mjs` importa este arquivo.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { load } from '../node.js';

const CORPUS = new URL('../../../themis/tests/dsl/corpus/', import.meta.url);
const LANGUAGES = ['blocks', 'rules', 'actors'];
const SCENARIOS = ['roles', 'relations', 'late', 'conditions'];
const source = (scenario, language) => readFileSync(new URL(`${scenario}.${language}.themis`, CORPUS), 'utf8');
// A origem dos comentários diz de onde eles vieram, e isso muda com a sintaxe.
const content = (policy) => {
  const copy = structuredClone(policy);
  for (const note of copy.notes ?? []) delete note.origin;
  return copy;
};
const failure = (fn) => {
  try {
    fn();
  } catch (error) {
    return error;
  }
  assert.fail('devia lançar');
};

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

const KINDS = 'language blocks\n\ntarget_kinds = [org]\n';
const READ = 'language blocks\n\npermission org.read {\n  targets = [org]\n}\n'; // sem o kind: não vale
const kindWith = (kind) => `${'language blocks'}\n\ntarget_kinds = [${kind}]\n\npermission ${kind}.read {\n  targets = [${kind}]\n}\n`;
const ORG = kindWith('org');
const DOC = kindWith('doc');
const TEAM = kindWith('team');
const codes = {};

for (const backend of ['native', 'wasm']) {
  const themis = await load({ backend });

  await test(`${backend}: os três tipos dão o mesmo JSON`, () => {
    for (const scenario of SCENARIOS) {
      const [blocks, rules, actors] = LANGUAGES.map((l) => content(themis.compile(source(scenario, l))));
      assert.deepEqual(rules, blocks, scenario);
      assert.deepEqual(actors, blocks, scenario);
    }
  });

  await test(`${backend}: ida e volta pelo JSON em cada tipo`, () => {
    for (const scenario of SCENARIOS) {
      for (const language of LANGUAGES) {
        const policy = themis.compile(source(scenario, language));
        const text = themis.print(policy, language);
        assert.deepEqual(content(themis.compile(text)), content(policy), `${scenario}.${language}`);
      }
    }
  });

  await test(`${backend}: convert entre todos os pares`, () => {
    for (const from of LANGUAGES) {
      for (const to of LANGUAGES) {
        const converted = themis.convert(source('roles', from), to);
        assert.ok(converted.includes(`language ${to}`), `${from} -> ${to}`);
        assert.deepEqual(content(themis.compile(converted)), content(themis.compile(source('roles', from))));
      }
    }
  });

  await test(`${backend}: erro de leitura traz posição e dica`, () => {
    const error = failure(() => themis.compile('language blocks\n\npermission {', { file: 'a.themis' }));
    assert.equal(error.code, 'DSL_PARSE');
    assert.ok(error instanceof Error);
    const [first] = error.diagnostics;
    assert.equal(first.file, 'a.themis');
    assert.equal(first.line, 3);
    assert.equal(typeof first.column, 'number');
    assert.equal(typeof first.message, 'string');
    assert.ok('hint' in first);
    codes.parse = [...(codes.parse ?? []), error.code];
  });

  await test(`${backend}: política que não vale é DSL_VALIDATE`, () => {
    const error = failure(() => themis.compile(READ));
    assert.equal(error.code, 'DSL_VALIDATE');
    assert.equal(error.diagnostics[0].file, '<input>');
    codes.validate = [...(codes.validate ?? []), error.code];
  });

  await test(`${backend}: projeto misto junta fontes de tipos diferentes`, () => {
    const policy = themis.loadProject([
      { path: 'org.themis', text: ORG },
      { path: 'doc.themis', text: themis.convert(DOC, 'rules') },
      { path: 'team.themis', text: themis.convert(TEAM, 'actors') },
    ]);
    assert.equal(policy.catalog.permissions[0].key, 'org.read');
    assert.deepEqual(policy.catalog.targetKinds, ['doc', 'org', 'team']);
    const reversed = themis.loadProject([
      { path: 'team.themis', text: themis.convert(TEAM, 'actors') },
      { path: 'doc.themis', text: themis.convert(DOC, 'rules') },
      { path: 'org.themis', text: ORG },
    ]);
    // Os kinds saem ordenados; a ordem das permissões é a das fontes, e não conta aqui.
    const byKey = (p) => ({ ...content(p), catalog: { ...p.catalog, permissions: [...p.catalog.permissions].sort((a, b) => a.key.localeCompare(b.key)) } });
    assert.deepEqual(byKey(reversed), byKey(policy));
    assert.deepEqual(policy.catalog.permissions.map((p) => p.key).sort(), ['doc.read', 'org.read', 'team.read']);
  });

  await test(`${backend}: conflito entre fontes aponta os dois lados`, () => {
    const full = ORG;
    const error = failure(() =>
      themis.loadProject([
        { path: 'a.themis', text: full },
        { path: 'b.themis', text: themis.convert(full, 'rules') },
      ]),
    );
    assert.equal(error.code, 'DSL_CONFLICT');
    const clash = error.diagnostics.find((d) => d.related);
    assert.ok(clash, 'um diagnóstico com os dois lados');
    assert.equal(clash.file, 'b.themis');
    assert.equal(clash.related.file, 'a.themis');
    assert.equal(typeof clash.related.line, 'number');
    codes.conflict = [...(codes.conflict ?? []), error.code];
  });

  await test(`${backend}: o que a sintaxe não diz é DSL_UNREPRESENTABLE`, () => {
    const policy = themis.compile(source('roles', 'blocks'));
    policy.notes = [
      { text: 'duas\nlinhas', anchor: { element: 'language', placement: 'before' }, origin: { file: 'f', language: 'blocks', line: 1, column: 1 } },
    ];
    for (const language of LANGUAGES) {
      const error = failure(() => themis.print(policy, language));
      assert.equal(error.code, 'DSL_UNREPRESENTABLE', language);
      codes.unrepresentable = [...(codes.unrepresentable ?? []), error.code];
    }
  });

  await test(`${backend}: argumento errado é INVALID_ARGUMENT`, () => {
    assert.equal(failure(() => themis.compile(1)).code, 'INVALID_ARGUMENT');
    assert.equal(failure(() => themis.convert(READ, 'yaml')).code, 'INVALID_ARGUMENT');
    assert.equal(failure(() => themis.loadProject('x')).code, 'INVALID_ARGUMENT');
    assert.equal(failure(() => themis.print({ nada: 1 }, 'blocks')).code, 'INVALID_INPUT');
  });

  await test(`${backend}: fonte repetida e fonte vazia`, () => {
    const dup = failure(() =>
      themis.loadProject([
        { path: 'a.themis', text: KINDS },
        { path: 'a.themis', text: KINDS },
      ]),
    );
    assert.equal(dup.code, 'DSL_PARSE');
    assert.equal(failure(() => themis.compile('')).code, 'DSL_PARSE');
  });
}

await test('N-API: loadProjectDir lê um diretório e o wasm não o tem', async () => {
  const native = await load({ backend: 'native' });
  const wasm = await load({ backend: 'wasm' });
  assert.equal(wasm.loadProjectDir, undefined);
  const dir = mkdtempSync(join(tmpdir(), 'themis-dsl-'));
  try {
    writeFileSync(join(dir, 'org.themis'), ORG);
    writeFileSync(join(dir, 'doc.themis'), native.convert(DOC, 'rules'));
    assert.equal(native.loadProjectDir(dir).catalog.permissions.length, 2);
    writeFileSync(join(dir, 'dup.themis'), DOC);
    assert.equal(failure(() => native.loadProjectDir(dir)).code, 'DSL_CONFLICT');
    assert.equal(failure(() => native.loadProjectDir(join(dir, 'nao-existe'))).code, 'DSL_IO');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

await test('paridade: os dois alvos dão os mesmos code e diagnósticos', async () => {
  for (const [name, list] of Object.entries(codes)) {
    assert.equal(list.length >= 2, true, name);
    assert.equal(new Set(list).size, 1, name);
  }
  const [native, wasm] = await Promise.all([load({ backend: 'native' }), load({ backend: 'wasm' })]);
  const bad = 'language blocks\n\npermission {';
  assert.deepEqual(failure(() => native.compile(bad)).diagnostics, failure(() => wasm.compile(bad)).diagnostics);
  assert.deepEqual(native.compile(source('roles', 'rules')), wasm.compile(source('roles', 'rules')));
});

if (failures > 0) process.exitCode = 1;
