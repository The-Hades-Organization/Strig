// Express middleware for Strig. The caller supplies how to read the subject, the permission and the resource.
import { createAuthorizer } from './web-core.js';

/**
 * Middleware that calls `next()` only on an allow. A deny answers 403 (configurable), an unreachable or failing
 * decision service answers 503, an unidentified caller 401 and an extractor error 500. It never lets a request pass otherwise.
 */
export function authorize(options) {
  return middleware(createAuthorizer(options));
}

/** `can(permission, resource?)` builds one middleware per route from shared options (`permission` and `resource` are replaced). */
export function createCan(options) {
  const decide = createAuthorizer(options);
  return (permission, resource) => {
    if (typeof permission !== 'string' || permission === '') throw new TypeError('permission must be a non-empty text');
    return middleware(decide, { permission, resource });
  };
}

// Express 4 does not catch a rejected promise: anything that escapes goes to `next(error)`, which refuses the request.
function middleware(decide, override) {
  return async function strigAuthorize(req, res, next) {
    let outcome;
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
