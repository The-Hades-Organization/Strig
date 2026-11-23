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

export type Reason =
  | { kind: 'override'; name: string }
  | { kind: 'grant'; grant_id: string; permission: string; rank: number; strategy: string }
  | { kind: 'no_applicable_grant' }
  | { kind: 'unknown_permission' }
  /** The permission would be allowed, but a `depends_on` prerequisite is not allowed on the same resource. */
  | { kind: 'missing_prerequisite'; permission: string; prerequisite: string };

export type Verdict =
  | { kind: 'candidate' }
  | { kind: 'candidate_fail_safe'; problem: string }
  | { kind: 'permission_unrelated' }
  | { kind: 'out_of_scope' }
  | { kind: 'target_not_on_path' }
  | { kind: 'subject_mismatch' }
  | { kind: 'subject_unresolved'; problem: string }
  | { kind: 'condition_false' }
  | { kind: 'condition_unresolved'; problem: string }
  /** The grant, or the requested permission, is `override_only`: grants are ignored. */
  | { kind: 'override_only' }
  | { kind: 'not_reached' };

export interface Decision {
  effect: 'allow' | 'deny';
  reason: Reason;
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
    verdict: Verdict;
    rank?: number;
    anchor?: { kind: string; id?: string };
    condition?: ConditionTrace;
  }>;
  /** Prerequisites (`depends_on`, transitive) consulted for an allowed permission, each with its outcome. */
  prerequisites?: Array<{ permission: string; allowed: boolean }>;
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

/**
 * Compensating change a refusal proposes. It names the subject by id and carries only the role;
 * nothing is applied. Send it back as an `assign_role` or `revoke_role` change with the stored subject.
 */
export type Suggestion =
  | { kind: 'assign_role'; subject_id: string; role: RoleAssignment }
  | { kind: 'revoke_role'; subject_id: string; role: RoleAssignment };

export interface ApplyResult {
  ok: boolean;
  grants?: Grant[];
  /** Subject with the role applied, on an accepted role change. */
  subject?: Subject;
  violations?: Array<{ invariant: string; message: string; suggestion?: Suggestion }>;
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
