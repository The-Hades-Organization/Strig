// One table that says which permission every route needs, shared by the express, fastify and nestjs integrations.
// Deny by default: a request no rule covers is refused (403). A route is public only when its rule says `public: true`.
import type { Resource } from './protocol.js';
import { createAuthorizer } from './web-core.js';
import type { AuthorizerOptions, Outcome } from './web-core.js';

export type RouteParams = Record<string, string>;

/**
 * One line of the table. `path` uses the frameworks' own syntax: literal segments, `:name` for one segment and a
 * trailing `*` for one or more segments (Express 5 `*name` and Fastify `*` are the same thing). Exactly one of
 * `permission` and `public: true` is given. `resource` has the shape of the `@Can` resolver plus the matched params:
 * at app level Express has not filled `req.params` yet, so read the id from `params`.
 */
export interface RouteRule<Req = any> {
  /** `'GET'`, `['GET', 'HEAD']` or `'*'` for any method. A HEAD request is covered by a GET rule. */
  method: string | readonly string[];
  path: string;
  permission?: string;
  public?: boolean;
  resource?: Resource | ((request: Req, params: RouteParams) => Resource);
}

export type RouteTableOptions<Req = any> = Omit<AuthorizerOptions<Req>, 'permission'> & {
  /** The table. The first rule that matches a request decides it, so write the specific ones first. */
  routes: readonly RouteRule<Req>[];
};

export interface RouteMatch<Req = any> {
  rule: RouteRule<Req>;
  params: RouteParams;
}

export interface CompiledRoutes<Req = any> {
  rules: readonly RouteRule<Req>[];
  /** The first rule that covers `method` and `url` (path with an optional query), or `undefined`. */
  match(method: string, url: string): RouteMatch<Req> | undefined;
}

interface Compiled<Req> {
  rule: RouteRule<Req>;
  methods: readonly string[];
  segments: readonly string[];
  wildcard: boolean;
}

const ANY = '*';

function compile<Req>(rule: RouteRule<Req>, index: number): Compiled<Req> {
  const where = `routes[${index}]`;
  if (rule === null || typeof rule !== 'object') throw new TypeError(`${where} must be an object`);
  const methods = (Array.isArray(rule.method) ? rule.method : [rule.method]).map((m: unknown) => {
    if (typeof m !== 'string' || m === '') throw new TypeError(`${where}.method must be a non-empty text or a list of them`);
    return m.toUpperCase();
  });
  if (methods.length === 0) throw new TypeError(`${where}.method must not be empty`);
  const isPublic = rule.public === true;
  if (isPublic === (rule.permission !== undefined)) throw new TypeError(`${where} needs exactly one of \`permission\` and \`public: true\``);
  if (!isPublic && (typeof rule.permission !== 'string' || rule.permission === '')) throw new TypeError(`${where}.permission must be a non-empty text`);
  if (isPublic && rule.resource !== undefined) throw new TypeError(`${where} is public: it takes no \`resource\``);
  if (typeof rule.path !== 'string' || !rule.path.startsWith('/')) throw new TypeError(`${where}.path must start with "/"`);
  const segments = rule.path === '/' ? [] : rule.path.split('/').slice(1);
  if (segments.length > 0 && segments[segments.length - 1] === '') segments.pop();
  segments.forEach((segment, i) => {
    const last = i === segments.length - 1;
    if (segment === '') throw new TypeError(`${where}.path has an empty segment`);
    if (segment.startsWith('*') && !last) throw new TypeError(`${where}.path: a wildcard is only valid as the last segment`);
    if (segment.startsWith(':') && (segment.length === 1 || /[?+*()]/.test(segment))) throw new TypeError(`${where}.path: "${segment}" is not a plain :name (write one rule per optional shape)`);
    if (!segment.startsWith(':') && !segment.startsWith('*') && /[:*()?]/.test(segment)) throw new TypeError(`${where}.path: "${segment}" mixes a pattern into a literal segment`);
  });
  const wildcard = segments.length > 0 && segments[segments.length - 1]!.startsWith('*');
  return { rule, methods, segments: wildcard ? segments.slice(0, -1) : segments, wildcard };
}

function requestSegments(url: string): string[] | undefined {
  const end = url.search(/[?#]/);
  const path = end < 0 ? url : url.slice(0, end);
  if (!path.startsWith('/')) return undefined;
  if (path === '/') return [];
  const parts = path.split('/').slice(1);
  if (parts[parts.length - 1] === '') parts.pop();
  return parts.includes('') ? undefined : parts;
}

function matchPath(entry: Compiled<any>, parts: readonly string[]): RouteParams | undefined {
  const { segments, wildcard } = entry;
  if (wildcard ? parts.length <= segments.length : parts.length !== segments.length) return undefined;
  const params: RouteParams = {};
  for (let i = 0; i < segments.length; i += 1) {
    const segment = segments[i]!;
    if (segment.startsWith(':')) {
      try {
        params[segment.slice(1)] = decodeURIComponent(parts[i]!);
      } catch {
        return undefined; // a malformed escape never matches: the request is refused
      }
    } else if (segment !== parts[i]) {
      return undefined;
    }
  }
  if (wildcard) params[ANY] = parts.slice(segments.length).join('/');
  return params;
}

/** Validates the table (a bad rule throws `TypeError` at startup, never at request time) and builds the matcher. */
export function compileRoutes<Req = any>(rules: readonly RouteRule<Req>[]): CompiledRoutes<Req> {
  if (!Array.isArray(rules)) throw new TypeError('routes must be an array of rules');
  const entries = rules.map(compile<Req>);
  return {
    rules,
    match(method, url) {
      const parts = requestSegments(url);
      if (!parts) return undefined;
      const verb = method.toUpperCase();
      for (const entry of entries) {
        const verbOk = entry.methods.some((m) => m === ANY || m === verb || (verb === 'HEAD' && m === 'GET'));
        const params = verbOk ? matchPath(entry, parts) : undefined;
        if (params) return { rule: entry.rule, params };
      }
      return undefined;
    },
  };
}

const refusal = (status: number, code: string, message: string): Outcome => ({ kind: code === 'forbidden' ? 'deny' : 'error', status, body: { error: { code, message } } });

/**
 * Builds the function the adapters call: it finds the rule for `locate(request)` and runs the usual decision with the
 * rule's permission and resource. No rule: deny. `public` rule: allow without reading the subject. A request whose
 * method or URL cannot be read is refused with `errorStatus`.
 */
export function createRouteDecider<Req = any>(
  options: RouteTableOptions<Req>,
  locate: (request: Req) => { method: string; url: string },
): (request: Req) => Promise<Outcome> {
  const { routes, ...rest } = options ?? ({} as RouteTableOptions<Req>);
  const table = compileRoutes(routes);
  const decide = createAuthorizer<Req>(rest);
  const denied = refusal(rest.denyStatus ?? 403, 'forbidden', 'access is denied');
  return async (request) => {
    let match: RouteMatch<Req> | undefined;
    try {
      const { method, url } = locate(request);
      match = table.match(method, url);
    } catch (error) {
      try {
        rest.onError?.(error, request);
      } catch {
        // the refusal stands whatever the logger does
      }
      return refusal(rest.errorStatus ?? 500, 'internal', 'the decision could not be computed; access is denied');
    }
    if (!match) return denied;
    const { rule, params } = match;
    if (rule.public) return { kind: 'allow' };
    const resource = typeof rule.resource === 'function' ? (req: Req) => (rule.resource as (r: Req, p: RouteParams) => Resource)(req, params) : rule.resource;
    return decide(request, { permission: rule.permission, resource });
  };
}
