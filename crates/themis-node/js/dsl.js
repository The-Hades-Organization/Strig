// A linguagem de políticas sobre o módulo nativo ou o wasm. As funções do binding devolvem
// `{ ok, value }` ou `{ ok: false, code, message, diagnostics }`; aqui o erro vira um `Error` com
// `code` e `diagnostics`, igual nos dois alvos.

function open(result) {
  if (result.ok) return result.value;
  const error = new Error(result.message);
  error.code = result.code;
  error.diagnostics = result.diagnostics;
  throw error;
}

/** @param {Record<string, Function | undefined>} raw as funções `dsl*` do binding */
export function makeDsl(raw) {
  const dsl = {
    compile: (text, options) => open(raw.dslCompile(text, options)),
    print: (policy, language) => open(raw.dslPrint(policy, language)),
    convert: (text, language) => open(raw.dslConvert(text, language)),
    format: (text, options) => open(raw.dslFormat(text, options)),
    isFormatted: (text, options) => open(raw.dslIsFormatted(text, options)),
    loadProject: (sources) => open(raw.dslLoadProject(sources)),
  };
  // Só o módulo nativo lê um diretório: o wasm não tem IO.
  if (typeof raw.dslLoadProjectDir === 'function') {
    dsl.loadProjectDir = (dir) => open(raw.dslLoadProjectDir(dir));
  }
  return dsl;
}
