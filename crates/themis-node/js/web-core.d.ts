import type { Context, Engine, Subject } from './index.js';
import type { Resource } from './protocol.js';
import type { RemoteClient } from './remote.js';

export interface LocalMode {
  engine: Engine;
  /** The grants to decide on; a function gets the request (per-tenant contexts). */
  context: Context | ((request: any) => Context);
  /** The instant, in ms UTC, given to every call (default `Date.now`). Inject it to control time. */
  now?: number | bigint | (() => number | bigint);
  /** Decide with `engine.checkFor` instead of `engine.decide`. */
  checkFor?: boolean;
  /** Subject reference for `checkFor` (default `{ type: subject.kind, id: subject.id }`). */
  subjectRef?: (request: any) => { type: string; id?: string };
}

export interface AuthorizerOptions<Req = any> {
  /** The caller. `null` or `undefined` answers 401. */
  subject: (request: Req) => Subject | null | undefined;
  permission?: string | ((request: Req) => string);
  resource?: Resource | ((request: Req) => Resource);
  /** Attributes for conditions (remote mode). */
  env?: (request: Req) => Record<string, unknown> | undefined;
  /** Exactly one of `local` and `remote`. */
  local?: LocalMode;
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

export type Outcome =
  | { kind: 'allow' }
  | { kind: 'deny' | 'failure' | 'unauthenticated' | 'error'; status: number; body: ErrorBody };

export declare function createAuthorizer<Req = any>(
  options: AuthorizerOptions<Req>,
): (request: Req, override?: { permission?: string; resource?: AuthorizerOptions<Req>['resource'] }) => Promise<Outcome>;

/** Thrown when an optional framework is not installed (at first use, never at import). Any other load error is rethrown. */
export declare class MissingPeerError extends Error {
  peer: string;
}
export declare function requirePeer(peer: string, subpath: string): any;
