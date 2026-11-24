// Navegador e Deno: WebAssembly.
import init, * as glue from '../wasm/strig.js';
import { makeDsl, type DslBinding } from './dsl.js';
import type { Strig } from './index.js';

let ready: Promise<Strig> | undefined;

export function load(options: { wasm?: string | URL | Response | BufferSource | WebAssembly.Module } = {}): Promise<Strig> {
  ready ??= init(options.wasm ? { module_or_path: options.wasm } : undefined).then(() => {
    const binding = glue as unknown as Pick<Strig, 'Engine' | 'Context' | 'Exclusive' | 'auditEstimate'> & DslBinding;
    return {
      Engine: binding.Engine,
      Context: binding.Context,
      auditEstimate: binding.auditEstimate,
      Exclusive: binding.Exclusive,
      ...makeDsl(binding),
      backend: 'wasm',
    } satisfies Strig;
  });
  return ready;
}

export * from './protocol.js';
