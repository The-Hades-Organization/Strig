import type { AuthorizerOptions } from './web-core.js';
import type { Resource } from './protocol.js';

export type { AuthorizerOptions, LocalMode, Outcome, ErrorBody } from './web-core.js';
export { MissingPeerError } from './web-core.js';
export { RemoteClient, CircuitBreaker } from './remote.js';

export declare const STRIG_CAN: string;

/** Declares the permission a handler or controller needs; `resolver(request)` returns the resource. */
export declare function Can(permission: string, resolver?: (request: any) => Resource): MethodDecorator & ClassDecorator;

interface ExecutionContextLike {
  getHandler(): Function;
  getClass(): Function;
  switchToHttp(): { getRequest(): any };
}

/** Use as `@UseGuards(new StrigGuard(options))`. Throws an `HttpException` on anything but an allow. */
export declare class StrigGuard {
  constructor(options: AuthorizerOptions);
  canActivate(context: ExecutionContextLike): Promise<boolean>;
}
