// A linguagem de políticas sobre o módulo nativo ou o wasm. As funções do binding devolvem
// `{ ok, value }` ou `{ ok: false, code, message, diagnostics }`; aqui o erro vira um `Error` com
// `code` e `diagnostics`, igual nos dois alvos.
import type {
  DslDiagnostic,
  DslError,
  NativePolicyLanguageApi,
  PolicyDocument,
  PolicyLanguage,
  PolicyLanguageApi,
  PolicySource,
  PolicyTestFile,
  PolicyTestReport,
} from './index.js';

type DslResult<T> = { ok: true; value: T } | { ok: false; code: DslError['code']; message: string; diagnostics: DslDiagnostic[] };

type FileOption = { file?: string };

/** As funções `dsl*` do binding, nativo ou wasm. */
export interface DslBinding {
  dslCompile(text: string, options?: FileOption): DslResult<PolicyDocument>;
  dslPrint(policy: PolicyDocument, language: PolicyLanguage): DslResult<string>;
  dslConvert(text: string, language: PolicyLanguage): DslResult<string>;
  dslFormat(text: string, options?: FileOption): DslResult<string>;
  dslIsFormatted(text: string, options?: FileOption): DslResult<boolean>;
  dslLoadProject(sources: PolicySource[]): DslResult<PolicyDocument>;
  dslRunTests(policy: PolicyDocument, tests: (PolicyTestFile | string)[]): DslResult<PolicyTestReport>;
  dslLoadProjectDir?(dir: string): DslResult<PolicyDocument>;
}

function open<T>(result: DslResult<T>): T {
  if (result.ok) return result.value;
  const error = new Error(result.message) as DslError;
  error.code = result.code;
  error.diagnostics = result.diagnostics;
  throw error;
}

export function makeDsl(raw: DslBinding): PolicyLanguageApi & Partial<NativePolicyLanguageApi> {
  const dsl: PolicyLanguageApi & Partial<NativePolicyLanguageApi> = {
    compile: (text, options) => open(raw.dslCompile(text, options)),
    print: (policy, language) => open(raw.dslPrint(policy, language)),
    convert: (text, language) => open(raw.dslConvert(text, language)),
    format: (text, options) => open(raw.dslFormat(text, options)),
    isFormatted: (text, options) => open(raw.dslIsFormatted(text, options)),
    loadProject: (sources) => open(raw.dslLoadProject(sources)),
    runTests: (policy, tests) => open(raw.dslRunTests(policy, tests)),
  };
  // Só o módulo nativo lê um diretório: o wasm não tem IO.
  const loadProjectDir = raw.dslLoadProjectDir;
  if (typeof loadProjectDir === 'function') {
    dsl.loadProjectDir = (dir) => open(loadProjectDir.call(raw, dir));
  }
  return dsl;
}
