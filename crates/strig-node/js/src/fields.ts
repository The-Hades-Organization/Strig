// Máscara de resposta por campo: `pickAllowed(objeto, allowedFields(...))`.
import type { FieldSet } from './index.js';

const UNSAFE = new Set(['__proto__', 'constructor', 'prototype']);

type Bag = Record<string, unknown>;

const isBag = (value: unknown): value is Bag =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const safe = (path: string[]): boolean => path.every((key) => !UNSAFE.has(key));

function copyPath(from: Bag, into: Bag, path: string[]): void {
  const [head, ...rest] = path as [string, ...string[]];
  if (!Object.hasOwn(from, head)) return;
  if (rest.length === 0) {
    into[head] = from[head];
    return;
  }
  const source = from[head];
  if (!isBag(source)) return;
  const target = isBag(into[head]) ? (into[head] as Bag) : {};
  into[head] = target;
  copyPath(source, target, rest);
}

function omitPath(bag: Bag, path: string[]): void {
  const [head, ...rest] = path as [string, ...string[]];
  if (!Object.hasOwn(bag, head)) return;
  if (rest.length === 0) {
    delete bag[head];
    return;
  }
  const inner = bag[head];
  if (!isBag(inner)) return;
  const copy = { ...inner };
  bag[head] = copy;
  omitPath(copy, rest);
}

/**
 * A copy of `value` with only the fields of `fields` (what `Engine.allowedFields` answers).
 * Dotted fields (`address.street`) reach into nested objects; a field that names an object takes it
 * whole. `none` gives `{}`; `all` gives a shallow copy; `all_except` gives a copy without those fields.
 * The input is never changed.
 */
export function pickAllowed<T extends object>(value: T, fields: FieldSet): Partial<T> {
  const source = value as unknown as Bag;
  switch (fields.kind) {
    case 'all':
      return { ...source } as Partial<T>;
    case 'none':
      return {};
    case 'only': {
      const out: Bag = {};
      for (const field of fields.fields) {
        const path = field.split('.');
        if (safe(path)) copyPath(source, out, path);
      }
      return out as Partial<T>;
    }
    case 'all_except': {
      const out: Bag = { ...source };
      for (const field of fields.fields) {
        const path = field.split('.');
        if (safe(path)) omitPath(out, path);
      }
      return out as Partial<T>;
    }
    default:
      return {};
  }
}
