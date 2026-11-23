// Express middleware for Themis. The caller supplies how to read the subject, the permission and the resource.
import { createAuthorizer, requirePeer } from './web-core.js';

await requirePeer('express', 'express');

/**
 * Middleware that calls `next()` only on an allow. A deny answers 403 (configurable), an unreachable or failing
 * decision service answers 503, an unidentified caller 401 and an extractor error 500. It never lets a request pass otherwise.
 */
export function authorize(options) {
  const decide = createAuthorizer(options);
  return async function themisAuthorize(req, res, next) {
    const outcome = await decide(req);
    if (outcome.kind === 'allow') return next();
    res.status(outcome.status).json(outcome.body);
  };
}

/** `can(permission, resource?)` builds one middleware per route from shared options (`permission` and `resource` are replaced). */
export function createCan(options) {
  const decide = createAuthorizer({ ...options, permission: options.permission ?? '-' });
  return (permission, resource) => async (req, res, next) => {
    const outcome = await decide(req, { permission, resource });
    if (outcome.kind === 'allow') return next();
    res.status(outcome.status).json(outcome.body);
  };
}

export { MissingPeerError } from './web-core.js';
export { RemoteClient, CircuitBreaker } from './remote.js';
