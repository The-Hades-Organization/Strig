// Test helpers for a central route table: list the routes of an app, then check the table against them.
// `assertRoutesCovered(expressRoutes(app), table)` in the host's own test suite fails when a route has no rule
// (it would be refused in production) or a rule has no route (a stale or shadowed line).
import { METHODS } from 'node:http';
import { compileRoutes } from './route-table.js';
import type { RouteRule } from './route-table.js';

export interface RouteInfo {
  /** Upper case; `'*'` for a route registered for every method. */
  method: string;
  path: string;
}

export interface RouteAudit<Req = any> {
  /** Routes no rule covers: they answer 403. */
  uncovered: RouteInfo[];
  /** Rules that decide no route: a typo, a removed route, or a rule hidden behind an earlier one. */
  unusedRules: RouteRule<Req>[];
  ok: boolean;
}

export class RouteTableAuditError extends Error {
  readonly audit: RouteAudit;

  constructor(audit: RouteAudit) {
    const rules = audit.unusedRules.map((r) => `${[r.method].flat().join('|')} ${r.path}`);
    super(
      [
        audit.uncovered.length > 0 ? `routes with no rule:\n  ${audit.uncovered.map((r) => `${r.method} ${r.path}`).join('\n  ')}` : '',
        rules.length > 0 ? `rules with no route:\n  ${rules.join('\n  ')}` : '',
      ]
        .filter(Boolean)
        .join('\n'),
    );
    this.name = 'RouteTableAuditError';
    this.audit = audit;
  }
}

const SAMPLE = 'strig-sample';

// A concrete path every request of the route pattern could take, so the table can be asked about it.
function sample(path: string): string {
  const segments = path.split('/').slice(1).filter((s, i, all) => !(s === '' && i === all.length - 1));
  const concrete = segments.map((s) => (s.startsWith(':') ? SAMPLE : s.startsWith('*') ? `${SAMPLE}/${SAMPLE}` : s));
  return `/${concrete.join('/')}`;
}

export function auditRoutes<Req = any>(routes: readonly RouteInfo[], table: readonly RouteRule<Req>[], options: { caseSensitive?: boolean } = {}): RouteAudit<Req> {
  const compiled = compileRoutes(table);
  const used = new Set<RouteRule<Req>>();
  const uncovered: RouteInfo[] = [];
  for (const route of routes) {
    const match = compiled.match(route.method, sample(route.path), options.caseSensitive);
    if (match) used.add(match.rule);
    else uncovered.push(route);
  }
  const unusedRules = table.filter((rule) => !used.has(rule));
  return { uncovered, unusedRules, ok: uncovered.length === 0 && unusedRules.length === 0 };
}

/** Throws `RouteTableAuditError` (with the full `audit`) unless every route has a rule and every rule has a route. Pass `caseSensitive: false` for an Express app, so the check compares the way its requests are matched. */
export function assertRoutesCovered<Req = any>(routes: readonly RouteInfo[], table: readonly RouteRule<Req>[], options: { caseSensitive?: boolean } = {}): void {
  const audit = auditRoutes(routes, table, options);
  if (!audit.ok) throw new RouteTableAuditError(audit);
}

// ---- Express ----

interface ExpressLayer {
  route?: { path: unknown; methods?: Record<string, boolean> };
  handle?: { stack?: ExpressLayer[] };
  rawPath?: unknown;
  regexp?: RegExp & { fast_slash?: boolean };
  keys?: { name: string | number }[];
}

// Express 5 keeps the mount path in `rawPath`; Express 4 only has a regexp, which is read back for plain `/a/:b` paths.
function mountPath(layer: ExpressLayer): string {
  if (typeof layer.rawPath === 'string') return layer.rawPath === '/' ? '' : layer.rawPath;
  const { regexp } = layer;
  if (regexp?.fast_slash) return '';
  let keys = 0;
  const text = regexp?.source
    .replace(/^\^/, '')
    .replace('\\/?(?=\\/|$)', '')
    .replace('(?:([^\\/]+?))', () => `:${layer.keys?.[keys++]?.name ?? 'p'}`)
    .replace(/\\\//g, '/');
  if (text === undefined || /[\\^$()[\]|?*+]/.test(text)) throw new Error('cannot read the mount path of a nested router; audit that router on its own with `expressRoutes(router, prefix)`');
  return text;
}

function walk(stack: readonly ExpressLayer[], prefix: string, out: RouteInfo[]): void {
  for (const layer of stack) {
    if (layer.route) {
      const path = typeof layer.route.path === 'string' ? layer.route.path : String(layer.route.path);
      const methods = Object.keys(layer.route.methods ?? {}).filter((m) => layer.route!.methods![m]);
      // `app.all` registers every method one by one in Express 5, so "all of them" is how it is told apart
      const forAll = methods.length === 0 || methods.includes('_all') || METHODS.every((m) => methods.includes(m.toLowerCase()) || m === 'HEAD');
      const verbs = forAll ? ['*'] : methods.map((m) => m.toUpperCase());
      for (const method of verbs) out.push({ method, path: `${prefix}${path === '/' && prefix ? '' : path}` });
    } else if (Array.isArray(layer.handle?.stack)) {
      walk(layer.handle.stack, `${prefix}${mountPath(layer)}`, out);
    }
  }
}

/**
 * Routes of an Express app or router (4 or 5), nested routers included. Call it after every route is registered.
 * Sub-apps mounted with `app.use('/x', subApp)` are not followed: audit them on their own.
 */
export function expressRoutes(app: unknown, prefix = ''): RouteInfo[] {
  const a = app as { router?: { stack?: ExpressLayer[] }; _router?: { stack?: ExpressLayer[] }; stack?: ExpressLayer[] };
  const stack = a.stack ?? a.router?.stack ?? a._router?.stack;
  if (!Array.isArray(stack)) throw new TypeError('not an Express app or router (no route stack found)');
  const out: RouteInfo[] = [];
  walk(stack, prefix, out);
  return out;
}

// ---- Fastify ----

interface FastifyRouteHooks {
  addHook(name: 'onRoute', hook: (options: { method: string | string[]; url: string }) => void): unknown;
}

/**
 * Fastify cannot list routes after the fact: call this on the instance BEFORE registering routes and plugins, and read
 * the returned array once the app is `ready()`. Routes of every plugin registered later are collected.
 */
export function collectFastifyRoutes(fastify: FastifyRouteHooks): RouteInfo[] {
  const out: RouteInfo[] = [];
  fastify.addHook('onRoute', (options) => {
    for (const method of [options.method].flat()) out.push({ method: method.toUpperCase(), path: options.url });
  });
  return out;
}

// ---- NestJS ----

/**
 * Routes of an initialized Nest app on the Express adapter (`await app.init()` first; the global prefix is included).
 * On the Fastify adapter use `collectFastifyRoutes(app.getHttpAdapter().getInstance())` before `app.init()`.
 */
export function nestRoutes(app: { getHttpAdapter(): { getInstance(): unknown } }): RouteInfo[] {
  const instance = app.getHttpAdapter().getInstance() as { addHook?: unknown };
  if (typeof instance.addHook === 'function') throw new TypeError('the Fastify adapter cannot be listed after init: use collectFastifyRoutes(app.getHttpAdapter().getInstance()) before app.init()');
  return expressRoutes(instance);
}
