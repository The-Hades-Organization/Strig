// Express middleware for Strig. The caller supplies how to read the subject, the permission and the resource.
import type { Resource } from './protocol.js';
import { createAuthorizer } from './web-core.js';
import type { AuthorizerOptions, Outcome, Override } from './web-core.js';
import { createRouteDecider } from './route-table.js';
import type { RouteTableOptions } from './route-table.js';

export type { AuthorizerOptions, LocalMode, Outcome, ErrorBody } from './web-core.js';
export type { RouteRule, RouteTableOptions, RouteParams } from './route-table.js';

type Next = (error?: unknown) => void;

// The request and response types are the caller's Express ones; the middleware only needs `status().json()`.
interface ExpressResponse {
  status(code: number): { json(body: unknown): unknown };
}

type Handler<Req> = (req: Req, res: ExpressResponse, next: Next) => Promise<void>;

/**
 * Middleware that calls `next()` only on an allow. A deny answers 403 (configurable), an unreachable or failing
 * decision service answers 503, an unidentified caller 401 and an extractor error 500. It never lets a request pass otherwise.
 */
export function authorize<Req = any>(options: AuthorizerOptions<Req>): Handler<Req> {
  return middleware(createAuthorizer(options));
}

/** `can(permission, resource?)` builds one middleware per route from shared options (`permission` and `resource` are replaced). */
export function createCan<Req = any>(
  options: AuthorizerOptions<Req>,
): (permission: string, resource?: Resource | ((req: Req) => Resource)) => Handler<Req> {
  const decide = createAuthorizer(options);
  return (permission, resource) => {
    if (typeof permission !== 'string' || permission === '') throw new TypeError('permission must be a non-empty text');
    return middleware(decide, { permission, resource });
  };
}

/**
 * Global middleware for a central route table, deny by default: `app.use(authorizeRoutes({ routes, subject, local }))`
 * before the routers. A request no rule covers answers 403 (also for URLs that have no route: 404 becomes 403), a
 * `public: true` rule passes without reading the subject, any other rule runs the usual decision. It matches
 * `req.originalUrl`, so mounting under routers does not shift the paths. Answer CORS preflights (`OPTIONS`) before it
 * or give them a public rule. Per-route `can()` still works and runs after it, so it only narrows.
 */
export function authorizeRoutes<Req = any>(options: RouteTableOptions<Req>): Handler<Req> {
  const decide = createRouteDecider<Req>(options, (req: any) => ({ method: req.method, url: req.originalUrl ?? req.url }));
  return middleware(decide);
}

// Express 4 does not catch a rejected promise: anything that escapes goes to `next(error)`, which refuses the request.
function middleware<Req>(decide: (request: Req, override?: Override<Req>) => Promise<Outcome>, override?: Override<Req>): Handler<Req> {
  return async function strigAuthorize(req, res, next) {
    let outcome: Outcome;
    try {
      outcome = await decide(req, override);
      if (outcome.kind !== 'allow') return void res.status(outcome.status).json(outcome.body);
    } catch (error) {
      return next(error);
    }
    return next();
  };
}

export { MissingPeerError } from './web-core.js';
export { RemoteClient, CircuitBreaker } from './remote.js';
