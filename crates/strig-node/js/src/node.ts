// Node e Bun: carrega o módulo nativo (N-API) e cai para o WebAssembly se ele não existir para a
// plataforma. STRIG_BACKEND=native|wasm força um dos dois.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { makeDsl, type DslBinding } from './dsl.js';
import type { Strig } from './index.js';

type Backend = 'auto' | 'native' | 'wasm';

type Binding = Pick<Strig, 'Engine' | 'Context' | 'Exclusive' | 'auditEstimate' | 'verifyAuditChain'> & DslBinding;

const require = createRequire(import.meta.url);
const cache = new Map<string, Promise<Strig>>();

function wrap(mod: Binding, backend: 'native' | 'wasm'): Strig {
  return {
    Engine: mod.Engine,
    Context: mod.Context,
    auditEstimate: mod.auditEstimate,
    verifyAuditChain: mod.verifyAuditChain,
    Exclusive: mod.Exclusive,
    ...makeDsl(mod),
    backend,
  };
}

async function loadWasm(): Promise<Strig> {
  const glue = await import('../wasm/strig.js');
  glue.initSync({ module: readFileSync(new URL('../wasm/strig_bg.wasm', import.meta.url)) });
  return wrap(glue as unknown as Binding, 'wasm');
}

const SCOPE = '@the-hades-organization';

function isGlibc(): boolean {
  const report = process.report?.getReport() as { header?: { glibcVersionRuntime?: string } } | undefined;
  return Boolean(report?.header?.glibcVersionRuntime);
}

// Keep in sync with scripts/platforms.json (the release script builds one package per entry).
function platformPackage(): string | undefined {
  const key = `${process.platform}-${process.arch}`;
  switch (key) {
    case 'linux-x64':
    case 'linux-arm64':
      return isGlibc() ? `strig-${key}-gnu` : undefined;
    case 'darwin-x64':
    case 'darwin-arm64':
      return `strig-${key}`;
    case 'win32-x64':
      return 'strig-win32-x64-msvc';
    default:
      return undefined;
  }
}

function loadNative(): Strig {
  const name = platformPackage();
  const errors: string[] = [];
  if (name) {
    try {
      return wrap(require(`${SCOPE}/${name}`) as Binding, 'native');
    } catch (error) {
      errors.push(String(error));
    }
  }
  // A local build (scripts/build.sh) leaves the module next to the sources.
  try {
    const file = new URL(`../native/strig.${process.platform}-${process.arch}.node`, import.meta.url);
    return wrap(require(fileURLToPath(file)) as Binding, 'native');
  } catch (error) {
    errors.push(String(error));
  }
  const platform = `${process.platform}-${process.arch}`;
  throw new Error(
    name
      ? `Strig: the native module ${SCOPE}/${name} for ${platform} could not be loaded. Install it with ` +
        `\`npm install ${SCOPE}/${name}\` (reinstall without --no-optional / --omit=optional), or set STRIG_BACKEND=wasm. ${errors.join(' | ')}`
      : `Strig: there is no native module for ${platform}${process.platform === 'linux' ? ' (only glibc is built)' : ''}; ` +
        'use the WebAssembly backend (STRIG_BACKEND=wasm).',
  );
}

export async function load(options: { backend?: Backend } = {}): Promise<Strig> {
  const wanted = options.backend ?? (process.env.STRIG_BACKEND as Backend | undefined) ?? 'auto';
  let loading = cache.get(wanted);
  if (!loading) {
    loading = (async () => {
      if (wanted === 'wasm') return loadWasm();
      try {
        return loadNative();
      } catch (error) {
        if (wanted === 'native') throw error;
        return loadWasm();
      }
    })();
    cache.set(wanted, loading);
  }
  return loading;
}

export * from './protocol.js';
