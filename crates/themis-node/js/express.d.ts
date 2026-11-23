import type { AuthorizerOptions } from './web-core.js';
import type { Resource } from './protocol.js';

export type { AuthorizerOptions, LocalMode, Outcome, ErrorBody } from './web-core.js';
export { MissingPeerError } from './web-core.js';
export { RemoteClient, CircuitBreaker } from './remote.js';

type Next = (error?: unknown) => void;
type Handler = (req: any, res: any, next: Next) => Promise<void>;

/** Calls `next()` only on an allow; otherwise answers 403, 503, 401 or 500 with `{ error: { code, message } }`. */
export declare function authorize(options: AuthorizerOptions): Handler;
/** One middleware per route: `app.get('/x', can('project.view', (req) => resource))`. */
export declare function createCan(options: AuthorizerOptions): (permission: string, resource?: Resource | ((req: any) => Resource)) => Handler;
