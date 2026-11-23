import type { Decision, Subject } from './index.js';
import type { Resource } from './protocol.js';

/** Codes of `crates/themis-server/API.md`. A code this client does not know arrives as `{ unknown: text }`. */
export type ErrorCode =
  | 'malformed_json' | 'invalid_request' | 'batch_too_large' | 'too_many_resources' | 'not_found'
  | 'method_not_allowed' | 'body_too_large' | 'unsupported_media_type' | 'source_unavailable'
  | 'query_limit_exceeded' | 'overloaded' | 'relation_depth_exceeded' | 'deadline_exceeded'
  | 'clock_unavailable' | 'internal';

export type FailureReason = 'circuit_open' | 'timeout' | 'unreachable' | 'server' | 'rejected' | 'invalid_response' | 'unexpected_status';

export interface Failure {
  reason: FailureReason;
  status?: number;
  code?: ErrorCode | { unknown: string };
  /** Fixed text of ours for a known code; the server's own text is never carried. */
  message?: string;
}

export interface CheckInput {
  subject: Subject;
  permission: string;
  resource: Resource;
  env?: Record<string, unknown>;
}

export interface RemoteResult {
  /** `true` only for a `200` whose `decision.effect` is `allow`. */
  allowed: boolean;
  decision?: Decision;
  evaluatedAt?: number;
  failure?: Failure;
}

export interface BreakerOptions {
  /** Consecutive failures that open the circuit (default 5). */
  failureThreshold?: number;
  /** How long an open circuit refuses calls, in ms (default 30000). */
  waitMs?: number;
  /** Monotonic clock in ms; inject it in tests (default `performance.now`). */
  clock?: () => number;
}

export declare class CircuitBreaker {
  constructor(options?: BreakerOptions);
  readonly state: 'closed' | 'open' | 'half-open';
  readonly generation: number;
  acquire(): { generation: number; probe: boolean } | null;
  success(permit: { generation: number }): void;
  failure(permit: { generation: number }): void;
}

export interface RemoteOptions {
  url: string;
  /** Per call, also sent as `x-themis-timeout-ms` (default 2000). */
  timeoutMs?: number;
  fetch?: typeof fetch;
  headers?: Record<string, string>;
  breaker?: BreakerOptions;
}

/** Never throws on a decision: every failure is `allowed: false` with a `failure`. */
export declare class RemoteClient {
  constructor(options: RemoteOptions);
  readonly breaker: CircuitBreaker;
  check(request: CheckInput): Promise<RemoteResult>;
  /** One call; answers keep the request order. A failed call denies every check with the same failure. */
  checkBatch(requests: CheckInput[]): Promise<RemoteResult[]>;
}

export declare const ERROR_MESSAGES: Readonly<Record<string, string>>;
export declare function messageFor(code: string): string;
export declare function parseErrorCode(value: unknown): ErrorCode | { unknown: string };
