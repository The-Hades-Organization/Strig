// NestJS integration for Strig: the `@Can(permission, resolver?)` decorator and `StrigGuard`.
import type { Resource } from './protocol.js';
import { createAuthorizer, requirePeer } from './web-core.js';
import type { AuthorizerOptions, Outcome } from './web-core.js';

export type { AuthorizerOptions, LocalMode, Outcome, ErrorBody } from './web-core.js';

interface ExecutionContextLike {
  getHandler(): Function;
  getClass(): Function;
  getType?(): string;
  switchToHttp(): { getRequest(): any };
}

interface CanMetadata {
  permission: string;
  resolver?: (request: any) => Resource;
}

interface NestCommon {
  SetMetadata(key: string, value: unknown): MethodDecorator & ClassDecorator;
  HttpException: new (response: unknown, status: number) => Error;
}

// `reflect-metadata` is the Nest project's own: it installs these on `Reflect` before any guard runs.
const reflect = Reflect as unknown as { getMetadata(key: string, target: object): CanMetadata | undefined };

// Loaded on first use, not at import, so `require('@the-hades-organization/strig/nestjs')` works from a CommonJS Nest project.
let nest: NestCommon | undefined;
const peer = (): NestCommon => (nest ??= requirePeer('@nestjs/common', 'nestjs'));

export const STRIG_CAN: string = 'strig:can';

/**
 * Declares the permission a handler (or a controller) needs. `resolver(request)` returns the resource and wins over the
 * guard's default `resource`. Without the guard nothing is checked, and a guarded handler without `@Can` is refused.
 */
export function Can(permission: string, resolver?: (request: any) => Resource): MethodDecorator & ClassDecorator {
  if (typeof permission !== 'string' || permission === '') throw new TypeError('permission must be a non-empty text');
  return peer().SetMetadata(STRIG_CAN, { permission, resolver });
}

/**
 * `@UseGuards(new StrigGuard(options))`. The options are those of the express integration without `permission`.
 * A guarded route with no `@Can` answers 500 (`errorStatus`, and `onError` is called): a missing declaration closes,
 * it never opens, so as a global guard (`APP_GUARD`) there is no way to leave one route public. Only HTTP contexts
 * are supported: GraphQL, WebSocket and RPC contexts answer 500.
 */
export class StrigGuard {
  private readonly options: AuthorizerOptions;
  private readonly decide: ReturnType<typeof createAuthorizer>;

  constructor(options: AuthorizerOptions) {
    peer(); // fail at construction, not on the first request, when @nestjs/common is missing
    this.options = options;
    this.decide = createAuthorizer(options);
  }

  async canActivate(context: ExecutionContextLike): Promise<boolean> {
    const { HttpException } = peer();
    const http = (context.getType?.() ?? 'http') === 'http';
    const meta: CanMetadata | undefined = http
      ? (reflect.getMetadata(STRIG_CAN, context.getHandler()) ?? reflect.getMetadata(STRIG_CAN, context.getClass()))
      : undefined;
    const outcome = meta ? await this.decide(context.switchToHttp().getRequest(), { permission: meta.permission, resource: meta.resolver }) : this.#refuse(http, context);
    if (outcome.kind === 'allow') return true;
    throw new HttpException(outcome.body, outcome.status);
  }

  #refuse(http: boolean, context: ExecutionContextLike): Outcome {
    try {
      this.options.onError?.(new Error(http ? 'a guarded handler has no @Can' : `unsupported execution context: ${context.getType?.()}`), context);
    } catch {
      // the refusal stands whatever the logger does
    }
    const status = this.options.errorStatus ?? 500;
    return { kind: 'error', status, body: { error: { code: 'internal', message: 'the decision could not be computed; access is denied' } } };
  }
}

export { MissingPeerError } from './web-core.js';
export { RemoteClient, CircuitBreaker } from './remote.js';
