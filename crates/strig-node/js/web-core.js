// Shared by the web integrations (express, fastify, nestjs): turns a request into a decision and the decision
// into a status and a body. It never imports a framework. Whatever goes wrong becomes a refusal, never an allow.
import { createRequire } from 'node:module';
import { messageFor } from './remote.js';

const OWN_MESSAGES = {
  forbidden: 'access is denied',
  unauthenticated: 'the caller is not identified; access is denied',
};
const body = (code) => ({ error: { code, message: Object.hasOwn(OWN_MESSAGES, code) ? OWN_MESSAGES[code] : messageFor(code) } });

/** Thrown by `requirePeer` when an optional framework is not installed. */
export class MissingPeerError extends Error {
  constructor(peer, subpath, cause) {
    super(`@the-hades-organization/strig/${subpath} needs the optional peer dependency "${peer}". Install it with: npm install ${peer}`, { cause });
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
export function requirePeer(peer, subpath, load = nodeRequire) {
  try {
    return load(peer);
  } catch (error) {
    const missing = error?.code === 'MODULE_NOT_FOUND' || error?.code === 'ERR_MODULE_NOT_FOUND';
    if (missing && String(error.message).includes(`'${peer}'`)) throw new MissingPeerError(peer, subpath, error);
    throw error;
  }
}

function status(value, name) {
  if (!Number.isInteger(value) || value < 400 || value > 599) throw new TypeError(`${name} must be an integer from 400 to 599`);
  return value;
}

function pick(value, request, name) {
  if (typeof value === 'function') return value(request);
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
export function createAuthorizer(options) {
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

  const refuse = (kind, code) => ({ kind, status: statuses[kind], body: body(code) });
  // `onError` is the caller's code: if it throws, the request is still refused (503, the stable body) and nothing escapes.
  const failed = (error, request) => {
    try {
      options.onError?.(error, request);
    } catch {
      return refuse('failure', 'internal');
    }
    return refuse('error', 'internal');
  };

  return async function authorize(request, override = {}) {
    let subject;
    let permission;
    let resource;
    let env;
    try {
      subject = options.subject(request);
      if (typeof subject?.then === 'function') {
        Promise.resolve(subject).catch(() => {}); // the promise is dropped: its rejection must not go unhandled
        throw new TypeError('subject must be synchronous: resolve it before the authorizer runs');
      }
      if (subject === null || subject === undefined) return refuse('unauthenticated', 'unauthenticated');
      permission = pick(override.permission ?? options.permission, request, 'permission');
      resource = pick(override.resource ?? options.resource, request, 'resource');
      env = options.env?.(request);
      if (typeof permission !== 'string' || permission === '') throw new TypeError('permission must be a non-empty text');
    } catch (error) {
      return failed(error, request);
    }
    try {
      return local
        ? decideLocal(local, now, { subject, permission, resource }, request, refuse)
        : await decideRemote(remote, { subject, permission, resource, env }, refuse, (error) => failed(error, request));
    } catch (error) {
      return failed(error, request);
    }
  };
}

function decideLocal(local, now, input, request, refuse) {
  const at = typeof now === 'function' ? now() : now;
  const context = typeof local.context === 'function' ? local.context(request) : local.context;
  if (local.checkFor) {
    const ref = local.subjectRef?.(request) ?? { type: input.subject.kind, id: input.subject.id };
    const answer = local.engine.checkFor(context, ref, input.permission, input.resource, [input.subject], at);
    return answer.allowed === true ? { kind: 'allow' } : refuse('deny', 'forbidden');
  }
  const decision = local.engine.decide(context, input, at);
  return decision.effect === 'allow' ? { kind: 'allow' } : refuse('deny', 'forbidden');
}

const SERVICE_CODES = new Set(['source_unavailable', 'overloaded', 'deadline_exceeded']);

async function decideRemote(remote, input, refuse, report) {
  const answer = await remote.check(input);
  if (answer.allowed === true) return { kind: 'allow' };
  const { failure } = answer;
  if (!failure) return refuse('deny', 'forbidden');
  // Our own request was wrong (a 4xx, or a payload that does not serialize): not the service being down.
  if (failure.reason === 'rejected' || failure.reason === 'invalid_request') {
    return report(Object.assign(new Error(`the decision service refused the request (${failure.reason})`), { failure }));
  }
  // The code says which kind of unavailability; the server's own text is never echoed.
  const code = SERVICE_CODES.has(failure.code) ? failure.code : failure.reason === 'timeout' ? 'deadline_exceeded' : 'source_unavailable';
  const outcome = refuse('failure', code);
  report(Object.assign(new Error(`the decision service failed (${failure.reason})`), { failure }));
  return outcome;
}
