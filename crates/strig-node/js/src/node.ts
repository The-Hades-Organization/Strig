// Node e Bun: carrega o módulo nativo (N-API) e cai para o WebAssembly se ele não existir para a
// plataforma. STRIG_BACKEND=native|wasm força um dos dois.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { makeDsl, type DslBinding } from './dsl.js';
import type { Strig } from './index.js';

type Backend = 'auto' | 'native' | 'wasm';

type Binding = Pick<Strig, 'Engine' | 'Context' | 'Exclusive' | 'auditEstimate'> & DslBinding;

const require = createRequire(import.meta.url);
const cache = new Map<string, Promise<Strig>>();

function wrap(mod: Binding, backend: 'native' | 'wasm'): Strig {
  return {
    Engine: mod.Engine,
    Context: mod.Context,
    auditEstimate: mod.auditEstimate,
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

function loadNative(): Strig {
  const file = new URL(`../native/strig.${process.platform}-${process.arch}.node`, import.meta.url);
  return wrap(require(fileURLToPath(file)) as Binding, 'native');
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
