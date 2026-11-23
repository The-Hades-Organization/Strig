// Shared by the web integrations (express, fastify, nestjs): turns a request into a decision and the decision
// into a status and a body. It never imports a framework. Whatever goes wrong becomes a refusal, never an allow.
import { messageFor } from './remote.js';

const OWN_MESSAGES = {
  forbidden: 'access is denied',
  unauthenticated: 'the caller is not identified; access is denied',
};
const body = (code) => ({ error: { code, message: OWN_MESSAGES[code] ?? messageFor(code) } });

/** Thrown by `requirePeer` when an optional framework is not installed. */
export class MissingPeerError extends Error {
  constructor(peer, subpath, cause) {
    super(`themis-auth/${subpath} needs the optional peer dependency "${peer}". Install it with: npm install ${peer}`, { cause });
    this.name = 'MissingPeerError';
    this.peer = peer;
  }
}

/** Import an optional framework or fail with a message that says what to install. */
export async function requirePeer(peer, subpath) {
  try {
    return await import(peer);
  } catch (error) {
    throw new MissingPeerError(peer, subpath, error);
  }
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
  const statuses = {
    deny: options.denyStatus ?? 403,
    failure: options.failureStatus ?? 503,
    unauthenticated: options.unauthenticatedStatus ?? 401,
    error: options.errorStatus ?? 500,
  };
  const now = local?.now ?? Date.now;

  const refuse = (kind, code) => ({ kind, status: statuses[kind], body: body(code) });

  return async function authorize(request, override = {}) {
    let subject;
    let permission;
    let resource;
    let env;
    try {
      subject = options.subject(request);
      if (subject === null || subject === undefined) return refuse('unauthenticated', 'unauthenticated');
      permission = pick(override.permission ?? options.permission, request, 'permission');
      resource = pick(override.resource ?? options.resource, request, 'resource');
      env = options.env?.(request);
      if (typeof permission !== 'string' || permission === '') throw new TypeError('permission must be a non-empty text');
    } catch (error) {
      options.onError?.(error, request);
      return refuse('error', 'internal');
    }
    try {
      return local ? decideLocal(local, now, { subject, permission, resource }, request, refuse) : await decideRemote(remote, { subject, permission, resource, env }, refuse);
    } catch (error) {
      options.onError?.(error, request);
      return refuse('error', 'internal');
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

async function decideRemote(remote, input, refuse) {
  const answer = await remote.check(input);
  if (answer.allowed === true) return { kind: 'allow' };
  if (!answer.failure) return refuse('deny', 'forbidden');
  // A 4xx is the caller's request being wrong, not the service being down; it still opens nothing.
  const down = answer.failure.reason !== 'rejected';
  return refuse(down ? 'failure' : 'error', down ? 'source_unavailable' : 'internal');
}
