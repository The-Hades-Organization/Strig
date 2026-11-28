// Fast path of the decision calls: the request crosses the boundary as one string made by
// `JSON.stringify` instead of an object read property by property through N-API / wasm-bindgen, and
// the decision comes back as a string for `JSON.parse`. Only plain JSON data takes it; anything else
// (`undefined`, `NaN`, functions, bigints, class instances) keeps the original path and its errors.
type Method = (this: unknown, ...args: unknown[]) => unknown;

interface FastEngine {
  prototype: Record<string, unknown>;
}

const MAX_DEPTH = 32;
const installed = new WeakSet<object>();

function plainValue(value: unknown, depth: number): boolean {
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return true;
    case 'number':
      return Number.isFinite(value);
    case 'object': {
      if (value === null) return true;
      if (depth > MAX_DEPTH) return false;
      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i += 1) {
          if (!(i in value) || !plainValue(value[i], depth + 1)) return false;
        }
        return true;
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) return false;
      for (const key in value) {
        if (!plainValue((value as Record<string, unknown>)[key], depth + 1)) return false;
      }
      return true;
    }
    default:
      return false;
  }
}

/** Replaces the decision methods of `Engine` by wrappers that take the string path when they can. */
export function installFastPaths(binding: { Engine: unknown }): void {
  const engine = binding.Engine as FastEngine;
  const proto = engine.prototype;
  if (installed.has(proto)) return;
  installed.add(proto);

  const original = (name: string): Method => proto[name] as Method;
  const define = (name: string, value: Method): void => {
    Object.defineProperty(proto, name, { value, writable: true, configurable: true, enumerable: false });
  };

  const single = (name: string, fast: string, parse: boolean): void => {
    const slow = original(name);
    const quick = original(fast);
    define(name, function (this: unknown, context: unknown, request: unknown, now?: unknown) {
      if (!plainValue(request, 0)) return slow.call(this, context, request, now);
      const out = quick.call(this, context, JSON.stringify(request), now);
      return parse ? JSON.parse(out as string) : out;
    });
  };
  const many = (name: string, fast: string, parse: boolean): void => {
    const slow = original(name);
    const quick = original(fast);
    define(name, function (this: unknown, context: unknown, requests: unknown, now?: unknown) {
      if (!Array.isArray(requests) || !plainValue(requests, 0)) return slow.call(this, context, requests, now);
      const out = quick.call(this, context, JSON.stringify(requests), now);
      return parse ? JSON.parse(out as string) : out;
    });
  };

  single('check', 'checkJson', false);
  single('decide', 'decideJson', true);
  single('explain', 'explainJson', true);
  many('checkMany', 'checkManyJson', false);
  many('explainMany', 'explainManyJson', true);
}
