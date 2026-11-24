// A linguagem de políticas no binding, nos dois alvos (N-API e wasm). `run.mjs` importa este arquivo.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { load } from '../node.js';

const CORPUS = new URL('../../../strig/tests/dsl/corpus/', import.meta.url);
const LANGUAGES = ['blocks', 'rules', 'actors'];
const SCENARIOS = ['roles', 'relations', 'late', 'conditions'];
const source = (scenario, language) => readFileSync(new URL(`${scenario}.${language}.strig`, CORPUS), 'utf8');
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
const messages = [];

for (const backend of ['native', 'wasm']) {
  const strig = await load({ backend });

  await test(`${backend}: os três tipos dão o mesmo JSON`, () => {
    for (const scenario of SCENARIOS) {
      const [blocks, rules, actors] = LANGUAGES.map((l) => content(strig.compile(source(scenario, l))));
      assert.deepEqual(rules, blocks, scenario);
      assert.deepEqual(actors, blocks, scenario);
    }
  });

  await test(`${backend}: ida e volta pelo JSON em cada tipo`, () => {
    for (const scenario of SCENARIOS) {
      for (const language of LANGUAGES) {
        const policy = strig.compile(source(scenario, language));
        const text = strig.print(policy, language);
        assert.deepEqual(content(strig.compile(text)), content(policy), `${scenario}.${language}`);
      }
    }
  });

  await test(`${backend}: convert entre todos os pares`, () => {
    for (const from of LANGUAGES) {
      for (const to of LANGUAGES) {
        const converted = strig.convert(source('roles', from), to);
        assert.ok(converted.includes(`language ${to}`), `${from} -> ${to}`);
        assert.deepEqual(content(strig.compile(converted)), content(strig.compile(source('roles', from))));
      }
    }
  });

  await test(`${backend}: erro de leitura traz posição e dica`, () => {
    const error = failure(() => strig.compile('language blocks\n\npermission {', { file: 'a.strig' }));
    assert.equal(error.code, 'DSL_PARSE');
    assert.ok(error instanceof Error);
    const [first] = error.diagnostics;
    assert.equal(first.file, 'a.strig');
    assert.equal(first.line, 3);
    assert.equal(typeof first.column, 'number');
    assert.equal(typeof first.message, 'string');
    assert.ok('hint' in first);
    codes.parse = [...(codes.parse ?? []), error.code];
  });

  await test(`${backend}: política que não vale é DSL_VALIDATE`, () => {
    const error = failure(() => strig.compile(READ));
    assert.equal(error.code, 'DSL_VALIDATE');
    assert.equal(error.diagnostics[0].file, '<input>');
    codes.validate = [...(codes.validate ?? []), error.code];
  });

  await test(`${backend}: projeto misto junta fontes de tipos diferentes`, () => {
    const policy = strig.loadProject([
      { path: 'org.strig', text: ORG },
      { path: 'doc.strig', text: strig.convert(DOC, 'rules') },
      { path: 'team.strig', text: strig.convert(TEAM, 'actors') },
    ]);
    assert.equal(policy.catalog.permissions[0].key, 'org.read');
    assert.deepEqual(policy.catalog.targetKinds, ['doc', 'org', 'team']);
    const reversed = strig.loadProject([
      { path: 'team.strig', text: strig.convert(TEAM, 'actors') },
      { path: 'doc.strig', text: strig.convert(DOC, 'rules') },
      { path: 'org.strig', text: ORG },
    ]);
    // Os kinds saem ordenados; a ordem das permissões é a das fontes, e não conta aqui.
    const byKey = (p) => ({ ...content(p), catalog: { ...p.catalog, permissions: [...p.catalog.permissions].sort((a, b) => a.key.localeCompare(b.key)) } });
    assert.deepEqual(byKey(reversed), byKey(policy));
    assert.deepEqual(policy.catalog.permissions.map((p) => p.key).sort(), ['doc.read', 'org.read', 'team.read']);
  });

  await test(`${backend}: conflito entre fontes aponta os dois lados`, () => {
    const full = ORG;
    const error = failure(() =>
      strig.loadProject([
        { path: 'a.strig', text: full },
        { path: 'b.strig', text: strig.convert(full, 'rules') },
      ]),
    );
    assert.equal(error.code, 'DSL_CONFLICT');
    const clash = error.diagnostics.find((d) => d.related);
    assert.ok(clash, 'um diagnóstico com os dois lados');
    assert.equal(clash.file, 'b.strig');
    assert.equal(clash.related.file, 'a.strig');
    assert.equal(typeof clash.related.line, 'number');
    codes.conflict = [...(codes.conflict ?? []), error.code];
  });

  await test(`${backend}: o que a sintaxe não diz é DSL_UNREPRESENTABLE`, () => {
    const policy = strig.compile(source('roles', 'blocks'));
    policy.notes = [
      { text: 'duas\nlinhas', anchor: { element: 'language', placement: 'before' }, origin: { file: 'f', language: 'blocks', line: 1, column: 1 } },
    ];
    for (const language of LANGUAGES) {
      const error = failure(() => strig.print(policy, language));
      assert.equal(error.code, 'DSL_UNREPRESENTABLE', language);
      codes.unrepresentable = [...(codes.unrepresentable ?? []), error.code];
    }
  });

  await test(`${backend}: format é canônico, idempotente e guarda os comentários`, () => {
    for (const scenario of SCENARIOS) {
      for (const language of LANGUAGES) {
        const text = source(scenario, language);
        const once = strig.format(text);
        assert.equal(strig.format(once), once, `${scenario} ${language}`);
        assert.equal(strig.isFormatted(once), true, `${scenario} ${language}`);
        assert.deepEqual(strig.compile(once).notes?.map((n) => n.text), strig.compile(text).notes?.map((n) => n.text));
      }
    }
    const messy = 'language blocks\n\n\n\ntarget_kinds = [org]   // kinds\n\npermission org.read {\n    targets = [org]\n}\n';
    const canonical = strig.format(messy);
    assert.equal(canonical, 'language blocks\n\ntarget_kinds = [org]  // kinds\n\npermission org.read {\n  targets = [org]\n}\n');
    assert.equal(strig.isFormatted(messy), false);
    assert.equal(strig.isFormatted(canonical), true);
  });

  await test(`${backend}: format de fonte inválida diz a posição`, () => {
    const error = failure(() => strig.format(READ, { file: 'x.strig' }));
    assert.equal(error.code, 'DSL_VALIDATE');
    assert.equal(error.diagnostics[0].file, 'x.strig');
    assert.equal(failure(() => strig.isFormatted('nada')).code, 'DSL_PARSE');
    assert.equal(failure(() => strig.format(1)).code, 'INVALID_ARGUMENT');
  });

  await test(`${backend}: argumento errado é INVALID_ARGUMENT`, () => {
    assert.equal(failure(() => strig.compile(1)).code, 'INVALID_ARGUMENT');
    assert.equal(failure(() => strig.convert(READ, 'yaml')).code, 'INVALID_ARGUMENT');
    assert.equal(failure(() => strig.loadProject('x')).code, 'INVALID_ARGUMENT');
    // A mensagem de argumento errado também é a mesma nos dois alvos.
    messages.push(failure(() => strig.compile(1)).message);
    assert.equal(failure(() => strig.print({ nada: 1 }, 'blocks')).code, 'INVALID_INPUT');
  });

  await test(`${backend}: fonte repetida e fonte vazia`, () => {
    const dup = failure(() =>
      strig.loadProject([
        { path: 'a.strig', text: KINDS },
        { path: 'a.strig', text: KINDS },
      ]),
    );
    assert.equal(dup.code, 'DSL_DUPLICATE_SOURCE');
    codes.duplicate = [...(codes.duplicate ?? []), dup.code];
    assert.equal(failure(() => strig.compile('')).code, 'DSL_PARSE');
  });
}

await test('N-API: loadProjectDir lê um diretório e o wasm não o tem', async () => {
  const native = await load({ backend: 'native' });
  const wasm = await load({ backend: 'wasm' });
  assert.equal(wasm.loadProjectDir, undefined);
  const dir = mkdtempSync(join(tmpdir(), 'strig-dsl-'));
  try {
    writeFileSync(join(dir, 'org.strig'), ORG);
    writeFileSync(join(dir, 'doc.strig'), native.convert(DOC, 'rules'));
    assert.equal(native.loadProjectDir(dir).catalog.permissions.length, 2);
    writeFileSync(join(dir, 'dup.strig'), DOC);
    assert.equal(failure(() => native.loadProjectDir(dir)).code, 'DSL_CONFLICT');
    assert.equal(failure(() => native.loadProjectDir(join(dir, 'nao-existe'))).code, 'DSL_IO');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

await test(`os dois alvos recusam o que passa dos limites`, async () => {
  for (const backend of ['native', 'wasm']) {
    const strig = await load({ backend });
    const big = `${KINDS}// ${'x'.repeat(4 * 1024 * 1024)}\n`;
    assert.equal(failure(() => strig.loadProject([{ path: 'big.strig', text: big }])).code, 'DSL_LIMIT', backend);
    // Mais de 100 diagnósticos: o corte é em 100 e o 101º diz quantos ficaram de fora.
    const many = Array.from({ length: 150 }, (_, i) => `permission org.p${i} {\n  targets = [org]\n}\n`).join('\n');
    const error = failure(() => strig.compile(`language blocks\n\n${many}`));
    assert.equal(error.diagnostics.length, 101, backend);
    assert.match(error.diagnostics.at(-1).message, /and \d+ more/, backend);
  }
});

await test('N-API: limites, links e diretório vazio em loadProjectDir', async () => {
  const native = await load({ backend: 'native' });
  const dir = mkdtempSync(join(tmpdir(), 'strig-dsl-lim-'));
  const outside = mkdtempSync(join(tmpdir(), 'strig-dsl-out-'));
  try {
    // diretório vazio: o que o núcleo já faz, uma política sem nada declarado
    const empty = join(dir, 'empty');
    mkdirSync(empty);
    assert.deepEqual(native.loadProjectDir(empty).catalog.permissions, []);

    // symlink para fora e para dentro: recusado, e a mensagem nomeia o arquivo
    const real = join(dir, 'real');
    mkdirSync(real);
    writeFileSync(join(outside, 'secret.strig'), ORG);
    symlinkSync(join(outside, 'secret.strig'), join(real, 'out.strig'));
    let error = failure(() => native.loadProjectDir(real));
    assert.equal(error.code, 'DSL_IO');
    assert.ok(error.message.includes('out.strig'), error.message);
    rmSync(join(real, 'out.strig'));
    writeFileSync(join(real, 'a.strig'), ORG);
    symlinkSync(join(real, 'a.strig'), join(real, 'b.strig'));
    error = failure(() => native.loadProjectDir(real));
    assert.equal(error.code, 'DSL_IO');
    assert.ok(error.message.includes('b.strig'), error.message);

    // arquivo acima de 4 MiB
    const large = join(dir, 'large');
    mkdirSync(large);
    writeFileSync(join(large, 'big.strig'), `${KINDS}// ${'x'.repeat(4 * 1024 * 1024)}\n`);
    assert.equal(failure(() => native.loadProjectDir(large)).code, 'DSL_LIMIT');

    // mais de 1024 arquivos
    const many = join(dir, 'many');
    mkdirSync(many);
    for (let i = 0; i < 1025; i += 1) writeFileSync(join(many, `f${i}.strig`), KINDS);
    assert.equal(failure(() => native.loadProjectDir(many)).code, 'DSL_LIMIT');
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

await test('paridade: os dois alvos dão os mesmos code e diagnósticos', async () => {
  for (const [name, list] of Object.entries(codes)) {
    assert.equal(list.length >= 2, true, name);
    assert.equal(new Set(list).size, 1, name);
  }
  const [native, wasm] = await Promise.all([load({ backend: 'native' }), load({ backend: 'wasm' })]);
  const bad = 'language blocks\n\npermission {';
  assert.equal(new Set(messages).size, 1, 'mensagem de INVALID_ARGUMENT');
  assert.deepEqual(failure(() => native.compile(bad)).diagnostics, failure(() => wasm.compile(bad)).diagnostics);
  assert.deepEqual(native.compile(source('roles', 'rules')), wasm.compile(source('roles', 'rules')));
});

if (failures > 0) process.exitCode = 1;
