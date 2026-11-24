// Shared by the web integrations (express, fastify, nestjs): turns a request into a decision and the decision
// into a status and a body. It never imports a framework. Whatever goes wrong becomes a refusal, never an allow.
import { createRequire } from 'node:module';
import type { Context, Engine, Subject, SubjectRef } from './index.js';
import type { Resource } from './protocol.js';
import { messageFor } from './remote.js';
import type { Failure, RemoteClient } from './remote.js';

// `any` keeps the request type the caller's framework gives it (Express `Request`, Fastify `FastifyRequest`, a Nest context's request).
export interface LocalMode<Req = any> {
  engine: Engine;
  /** The grants to decide on; a function gets the request (per-tenant contexts). */
  context: Context | ((request: Req) => Context);
  /** The instant, in ms UTC, given to every call (default `Date.now`). Inject it to control time. */
  now?: number | bigint | (() => number | bigint);
  /** Decide with `engine.checkFor` instead of `engine.decide`. */
  checkFor?: boolean;
  /** Subject reference for `checkFor` (default `{ type: subject.kind, id: subject.id }`). */
  subjectRef?: (request: Req) => { type: string; id?: string };
}

export interface AuthorizerOptions<Req = any> {
  /** The caller. `null` or `undefined` answers 401. */
  subject: (request: Req) => Subject | null | undefined;
  permission?: string | ((request: Req) => string);
  resource?: Resource | ((request: Req) => Resource);
  /** Attributes for conditions (remote mode). */
  env?: (request: Req) => Record<string, unknown> | undefined;
  /** Exactly one of `local` and `remote`. */
  local?: LocalMode<Req>;
  remote?: RemoteClient;
  /** Default 403. Every status must be an integer from 400 to 599. */
  denyStatus?: number;
  /** Remote service down, timeout or open circuit. Default 503. */
  failureStatus?: number;
  /** Default 401. */
  unauthenticatedStatus?: number;
  /** An extractor or the engine threw. Default 500. */
  errorStatus?: number;
  /** Called with the error before the generic refusal goes out (also for a failed or refused remote call, with `error.failure`). If it throws, the answer is 503. The error never reaches the client. */
  onError?: (error: unknown, request: Req) => void;
}

export interface ErrorBody {
  error: { code: string; message: string };
}

type RefusalKind = 'deny' | 'failure' | 'unauthenticated' | 'error';

export type Outcome = { kind: 'allow' } | { kind: RefusalKind; status: number; body: ErrorBody };

export type Override<Req> = { permission?: string; resource?: AuthorizerOptions<Req>['resource'] };

type Refuse = (kind: RefusalKind, code: string) => Outcome;

const OWN_MESSAGES: Record<string, string> = {
  forbidden: 'access is denied',
  unauthenticated: 'the caller is not identified; access is denied',
};
const body = (code: string): ErrorBody => ({ error: { code, message: Object.hasOwn(OWN_MESSAGES, code) ? OWN_MESSAGES[code]! : messageFor(code) } });

/** Thrown by `requirePeer` when an optional framework is not installed. */
export class MissingPeerError extends Error {
  readonly peer: string;

  constructor(peer: string, subpath: string, cause: unknown) {
    super(`strig/${subpath} needs the optional peer dependency "${peer}". Install it with: npm install ${peer}`, { cause });
    this.name = 'MissingPeerError';
    this.peer = peer;
  }
}

const nodeRequire = createRequire(import.meta.url);

/**
 * Load an optional framework, synchronously and when first needed (never at import, so `require()` of the subpaths
 * works). Only "this package is not installed" becomes a `MissingPeerError`; any other error is rethrown as it is.
 * `load` is for tests.
 */
export function requirePeer(peer: string, subpath: string, load: (id: string) => any = nodeRequire): any {
  try {
    return load(peer);
  } catch (error) {
    const { code, message } = (error ?? {}) as { code?: unknown; message?: unknown };
    const missing = code === 'MODULE_NOT_FOUND' || code === 'ERR_MODULE_NOT_FOUND';
    if (missing && String(message).includes(`'${peer}'`)) throw new MissingPeerError(peer, subpath, error);
    throw error;
  }
}

function status(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 400 || value > 599) throw new TypeError(`${name} must be an integer from 400 to 599`);
  return value;
}

function pick<Req, T>(value: T | ((request: Req) => T) | undefined, request: Req, name: string): T {
  if (typeof value === 'function') return (value as (request: Req) => T)(request);
  if (value === undefined) throw new TypeError(`${name} is required`);
  return value;
}

/**
 * Build the function that decides one request. Options (all functions come from the caller, nothing is inferred):
 * `subject(req)`, `permission` (text or `(req) => text`), `resource(req)`, plus one of
 * `local: { engine, context, now?, checkFor? }` or `remote: RemoteClient`.
 * `denyStatus` (403), `failureStatus` (503), `unauthenticatedStatus` (401) and `errorStatus` (500) can be changed.
 * The result is `{ kind: 'allow' } | { kind: 'deny' | 'failure' | 'unauthenticated' | 'error', status, body }`.
 */
export function createAuthorizer<Req = any>(options: AuthorizerOptions<Req>): (request: Req, override?: Override<Req>) => Promise<Outcome> {
  const { local, remote } = options ?? {};
  if (typeof options?.subject !== 'function') throw new TypeError('subject must be a function');
  if (Boolean(local) === Boolean(remote)) throw new TypeError('pass exactly one of `local` and `remote`');
  if (local && (!local.engine || !local.context)) throw new TypeError('local needs `engine` and `context`');
  if (remote && typeof remote.check !== 'function') throw new TypeError('remote must be a RemoteClient');
  const statuses = {
    deny: status(options.denyStatus ?? 403, 'denyStatus'),
    failure: status(options.failureStatus ?? 503, 'failureStatus'),
    unauthenticated: status(options.unauthenticatedStatus ?? 401, 'unauthenticatedStatus'),
    error: status(options.errorStatus ?? 500, 'errorStatus'),
  };
  const now = local?.now ?? Date.now;

  const refuse: Refuse = (kind, code) => ({ kind, status: statuses[kind], body: body(code) });
  // `onError` is the caller's code: if it throws, the request is still refused (503, the stable body) and nothing escapes.
  const failed = (error: unknown, request: Req): Outcome => {
    try {
      options.onError?.(error, request);
    } catch {
      return refuse('failure', 'internal');
    }
    return refuse('error', 'internal');
  };

  return async function authorize(request, override = {}) {
    let subject: Subject | null | undefined;
    let permission: string;
    let resource: Resource;
    let env: Record<string, unknown> | undefined;
    try {
      subject = options.subject(request);
      if (typeof (subject as { then?: unknown } | null | undefined)?.then === 'function') {
        Promise.resolve(subject).catch(() => {}); // the promise is dropped: its rejection must not go unhandled
        throw new TypeError('subject must be synchronous: resolve it before the authorizer runs');
      }
      if (subject === null || subject === undefined) return refuse('unauthenticated', 'unauthenticated');
      permission = pick<Req, string>(override.permission ?? options.permission, request, 'permission');
      resource = pick<Req, Resource>(override.resource ?? options.resource, request, 'resource');
      env = options.env?.(request);
      if (typeof permission !== 'string' || permission === '') throw new TypeError('permission must be a non-empty text');
    } catch (error) {
      return failed(error, request);
    }
    try {
      return local
        ? decideLocal(local, now, { subject, permission, resource }, request, refuse)
        : await decideRemote(remote!, { subject, permission, resource, env }, refuse, (error) => failed(error, request));
    } catch (error) {
      return failed(error, request);
    }
  };
}

function decideLocal<Req>(
  local: LocalMode<Req>,
  now: number | bigint | (() => number | bigint),
  input: { subject: Subject; permission: string; resource: Resource },
  request: Req,
  refuse: Refuse,
): Outcome {
  const at = typeof now === 'function' ? now() : now;
  const context = typeof local.context === 'function' ? local.context(request) : local.context;
  if (local.checkFor) {
    const ref = (local.subjectRef?.(request) ?? { type: input.subject.kind, id: input.subject.id }) as SubjectRef;
    const answer = local.engine.checkFor(context, ref, input.permission, input.resource, [input.subject], at);
    return answer.allowed === true ? { kind: 'allow' } : refuse('deny', 'forbidden');
  }
  const decision = local.engine.decide(context, input, at);
  return decision.effect === 'allow' ? { kind: 'allow' } : refuse('deny', 'forbidden');
}

const SERVICE_CODES = new Set(['source_unavailable', 'overloaded', 'deadline_exceeded']);

async function decideRemote(
  remote: RemoteClient,
  input: { subject: Subject; permission: string; resource: Resource; env: Record<string, unknown> | undefined },
  refuse: Refuse,
  report: (error: Error) => Outcome,
): Promise<Outcome> {
  const answer = await remote.check(input);
  if (answer.allowed === true) return { kind: 'allow' };
  const { failure } = answer;
  if (!failure) return refuse('deny', 'forbidden');
  // Our own request was wrong (a 4xx, or a payload that does not serialize): not the service being down.
  if (failure.reason === 'rejected' || failure.reason === 'invalid_request') {
    return report(Object.assign(new Error(`the decision service refused the request (${failure.reason})`), { failure }));
  }
  // The code says which kind of unavailability; the server's own text is never echoed.
  const code = typeof failure.code === 'string' && SERVICE_CODES.has(failure.code) ? failure.code : failure.reason === 'timeout' ? 'deadline_exceeded' : 'source_unavailable';
  const outcome = refuse('failure', code);
  report(Object.assign(new Error(`the decision service failed (${failure.reason})`), { failure }));
  return outcome;
}
