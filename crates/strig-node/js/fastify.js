// Fastify `preHandler` for Strig. The caller supplies how to read the subject, the permission and the resource.
import { createAuthorizer } from './web-core.js';

/**
 * `preHandler` that lets the request continue only on an allow. A deny answers 403 (configurable), an unreachable or
 * failing decision service answers 503, an unidentified caller 401 and an extractor error 500.
 */
export function authorize(options) {
  const decide = createAuthorizer(options);
  return async function strigPreHandler(request, reply) {
    const outcome = await decide(request);
    if (outcome.kind === 'allow') return;
    return reply.code(outcome.status).send(outcome.body);
  };
}

/** `can(permission, resource?)` builds one `preHandler` per route from shared options. */
export function createCan(options) {
  const decide = createAuthorizer(options);
  return (permission, resource) => {
    if (typeof permission !== 'string' || permission === '') throw new TypeError('permission must be a non-empty text');
    return async (request, reply) => {
      const outcome = await decide(request, { permission, resource });
      if (outcome.kind === 'allow') return;
      return reply.code(outcome.status).send(outcome.body);
    };
  };
}

/** Fastify plugin: `fastify.register(plugin, options)` adds `fastify.strigCan(permission, resource?)`. */
export async function plugin(fastify, options) {
  fastify.decorate('strigCan', createCan(options));
}
plugin[Symbol.for('skip-override')] = true;

export { MissingPeerError } from './web-core.js';
export { RemoteClient, CircuitBreaker } from './remote.js';
