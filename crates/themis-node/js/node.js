// Node e Bun: carrega o módulo nativo (N-API) e cai para o WebAssembly se ele não existir para a
// plataforma. THEMIS_BACKEND=native|wasm força um dos dois.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { makeDsl } from './dsl.js';

const require = createRequire(import.meta.url);
const cache = new Map();

function wrap(mod, backend) {
  return { Engine: mod.Engine, Context: mod.Context, auditEstimate: mod.auditEstimate, Exclusive: mod.Exclusive, ...makeDsl(mod), backend };
}

async function loadWasm() {
  const glue = await import('./wasm/themis.js');
  glue.initSync({ module: readFileSync(new URL('./wasm/themis_bg.wasm', import.meta.url)) });
  return wrap(glue, 'wasm');
}

function loadNative() {
  const file = new URL(`./native/themis.${process.platform}-${process.arch}.node`, import.meta.url);
  return wrap(require(fileURLToPath(file)), 'native');
}

/** @param {{ backend?: 'auto' | 'native' | 'wasm' }} [options] */
export async function load(options = {}) {
  const wanted = options.backend ?? process.env.THEMIS_BACKEND ?? 'auto';
  if (!cache.has(wanted)) {
    cache.set(
      wanted,
      (async () => {
        if (wanted === 'wasm') return loadWasm();
        try {
          return loadNative();
        } catch (error) {
          if (wanted === 'native') throw error;
          return loadWasm();
        }
      })(),
    );
  }
  return cache.get(wanted);
}

export * from './protocol.js';
