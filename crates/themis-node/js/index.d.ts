import type { Resource } from './protocol.js';

export * from './protocol.js';

export type AuditLevel = 'minimal' | 'standard' | 'detailed' | 'forensic';

export interface Subject {
  kind: string;
  id?: string;
  roles?: RoleAssignment[];
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

export interface Explanation {
  subject: Subject;
  permission: string;
  resource: Resource;
  effective: string[];
  path: Array<{ kind: string; id?: string }>;
  roles: string[];
  overrides: Array<{ name: string; outcome: 'excepted' | 'abstained' | 'allowed' | 'denied' }>;
  grants: Array<{
    grant: Grant;
    verdict: { kind: string; problem?: string };
    rank?: number;
    anchor?: { kind: string; id?: string };
    condition?: ConditionTrace;
  }>;
  strategy: string;
  decision: Decision;
}

export interface ConditionTrace {
  label: string;
  result: { kind: 'true' | 'false' | 'skipped' } | { kind: 'error'; detail: string };
  children?: ConditionTrace[];
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

export interface RoleAssignment {
  role: string;
  scope?: { kind: string; id?: string };
}

export interface ApplyInput {
  actor: Subject;
  current: Grant[];
  mutation:
    | { add: Grant }
    | { remove: { id: string } }
    | { assign_role: { subject: Subject; role: RoleAssignment } }
    | { revoke_role: { subject: Subject; role: RoleAssignment } };
  invariants?: unknown[];
  tuples?: unknown[];
  audit?: { level: AuditLevel; prevHash?: string };
  meta?: Record<string, unknown>;
}

export interface ApplyResult {
  ok: boolean;
  grants?: Grant[];
  /** Subject with the role applied, on an accepted role change. */
  subject?: Subject;
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
  /** A decisão com o rastro: overrides, destino de cada grant e árvore das condições. */
  explain(context: Context, request: DecisionRequest): Explanation;
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
