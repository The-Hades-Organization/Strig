import type { Resource } from './protocol.js';

export * from './protocol.js';

export type AuditLevel = 'minimal' | 'standard' | 'detailed' | 'forensic';

export interface Subject {
  kind: string;
  id?: string;
  roles?: Array<{ role: string; scope?: { kind: string; id?: string } }>;
  principals?: string[];
  attrs?: Record<string, unknown>;
}

export interface Grant {
  id: string;
  subject: { kind: 'user' | 'role'; id: string } | { kind: 'principal'; name: string } | { kind: 'relation'; relation: string } | { kind: 'any' };
  permission: string;
  target: { kind: string; id?: string };
  effect: 'allow' | 'deny';
  scope?: { kind: string; id?: string };
  condition?: unknown;
}

export interface Decision {
  effect: 'allow' | 'deny';
  reason: { kind: string; [key: string]: unknown };
  matched?: string[];
  warnings?: string[];
}

export interface CapabilitySet {
  subject: Subject;
  grants: Grant[];
}

export interface DecisionRequest {
  subject: Subject;
  permission: string;
  resource: Resource;
}

export interface ApplyInput {
  actor: Subject;
  current: Grant[];
  mutation: { add: Grant } | { remove: { id: string } };
  invariants?: unknown[];
  tuples?: unknown[];
  audit?: { level: AuditLevel; prevHash?: string };
  meta?: Record<string, unknown>;
}

export interface ApplyResult {
  ok: boolean;
  grants?: Grant[];
  violations?: Array<{ invariant: string; message: string }>;
  audit?: Record<string, unknown> | null;
}

export declare class Context {
  constructor(init?: { grants?: Grant[]; tuples?: unknown[]; env?: Record<string, unknown> });
  setGrants(grants: Grant[]): void;
  addGrant(grant: Grant): void;
  removeGrant(id: string): boolean;
  grants(): Grant[];
  readonly size: number;
  addTuple(tuple: unknown): boolean;
  removeTuple(tuple: unknown): boolean;
  setEnv(env: Record<string, unknown>): void;
  loadCapabilities(set: CapabilitySet): Subject;
}

export declare class Engine {
  /** `EngineSpec` da Themis: catálogo, papéis, relações, estratégia, overrides. */
  constructor(spec: unknown);
  decide(context: Context, request: DecisionRequest): Decision;
  check(context: Context, request: DecisionRequest): boolean;
  capabilities(context: Context, subject: Subject, scope: Resource): CapabilitySet;
  validateGrant(grant: Grant): void;
  catalog(): unknown;
  apply(input: ApplyInput): ApplyResult;
}

export interface Themis {
  Engine: typeof Engine;
  Context: typeof Context;
  auditEstimate(level: AuditLevel, records: number): number;
  backend: 'native' | 'wasm';
}

export function load(options?: { backend?: 'auto' | 'native' | 'wasm'; wasm?: unknown }): Promise<Themis>;
