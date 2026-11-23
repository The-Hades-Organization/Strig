// NestJS integration for Themis: the `@Can(permission, resolver?)` decorator and `ThemisGuard`.
import { createAuthorizer, requirePeer } from './web-core.js';

const { SetMetadata, HttpException } = await requirePeer('@nestjs/common', 'nestjs');

export const THEMIS_CAN = 'themis:can';

/**
 * Declares the permission a handler (or a controller) needs. `resolver(request)` returns the resource and wins over the
 * guard's default `resource`. Without the guard nothing is checked, and a guarded handler without `@Can` is refused.
 */
export function Can(permission, resolver) {
  if (typeof permission !== 'string' || permission === '') throw new TypeError('permission must be a non-empty text');
  return SetMetadata(THEMIS_CAN, { permission, resolver });
}

/**
 * `@UseGuards(new ThemisGuard(options))`. The options are those of the express integration without `permission`.
 * A guarded route with no `@Can` answers 500: a missing declaration closes, it never opens.
 */
export class ThemisGuard {
  constructor(options) {
    this.decide = createAuthorizer({ ...options, permission: options.permission ?? '-' });
  }

  async canActivate(context) {
    const meta = Reflect.getMetadata(THEMIS_CAN, context.getHandler()) ?? Reflect.getMetadata(THEMIS_CAN, context.getClass());
    const request = context.switchToHttp().getRequest();
    const outcome = meta
      ? await this.decide(request, { permission: meta.permission, resource: meta.resolver })
      : { kind: 'error', status: 500, body: { error: { code: 'internal', message: 'the decision could not be computed; access is denied' } } };
    if (outcome.kind === 'allow') return true;
    throw new HttpException(outcome.body, outcome.status);
  }
}

export { MissingPeerError } from './web-core.js';
export { RemoteClient, CircuitBreaker } from './remote.js';
