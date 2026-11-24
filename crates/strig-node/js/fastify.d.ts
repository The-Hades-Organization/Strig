import type { AuthorizerOptions } from './web-core.js';
import type { Resource } from './protocol.js';

export type { AuthorizerOptions, LocalMode, Outcome, ErrorBody } from './web-core.js';
export { MissingPeerError } from './web-core.js';
export { RemoteClient, CircuitBreaker } from './remote.js';

type PreHandler = (request: any, reply: any) => Promise<unknown>;

/** `preHandler` that lets the request on only on an allow; otherwise answers 403, 503, 401 or 500. */
export declare function authorize(options: AuthorizerOptions): PreHandler;
export declare function createCan(options: AuthorizerOptions): (permission: string, resource?: Resource | ((request: any) => Resource)) => PreHandler;
/** `fastify.register(plugin, options)` adds `fastify.strigCan(permission, resource?)`. */
export declare function plugin(fastify: any, options: AuthorizerOptions): Promise<void>;
