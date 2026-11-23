// Navegador e Deno: WebAssembly.
import init, * as glue from './wasm/themis.js';

let ready;

/** @param {{ wasm?: string | URL | Response | BufferSource | WebAssembly.Module }} [options] */
export function load(options = {}) {
  ready ??= init(options.wasm ? { module_or_path: options.wasm } : undefined).then(() => ({
    Engine: glue.Engine,
    Context: glue.Context,
    auditEstimate: glue.auditEstimate,
    Exclusive: glue.Exclusive,
    backend: 'wasm',
  }));
  return ready;
}

export * from './protocol.js';
