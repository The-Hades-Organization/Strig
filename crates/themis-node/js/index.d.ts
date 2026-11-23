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

/** Who a grant names. */
export type SubjectMatcher =
  | { kind: 'user' | 'role'; id: string }
  | { kind: 'principal'; name: string }
  | { kind: 'relation'; relation: string }
  | { kind: 'any' };

/** A reference to an object, by kind and id. */
export interface ObjectRef {
  kind: string;
  id: string;
}

/** Stable `code` of every error the binding throws (`error.code`). */
export type ErrorCode =
  | 'INVALID_INPUT'
  | 'INVALID_SPEC'
  | 'INVALID_GRANT'
  | 'UNKNOWN_SUBJECT'
  | 'QUERY_LIMIT_EXCEEDED'
  | 'RELATION_DEPTH_EXCEEDED'
  | 'QUERY_ERROR'
  | 'EXCLUSIVE_ZERO_TTL'
  | 'EXCLUSIVE_NOT_HELD'
  | 'EXCLUSIVE_NOT_HOLDER'
  | 'EXCLUSIVE_ANONYMOUS_SUBJECT'
  | 'EXCLUSIVE_UNIDENTIFIED_RESOURCE'
  | 'EXCLUSIVE_TTL_TOO_LONG'
  | 'EXCLUSIVE_DENIED'
  | 'EXCLUSIVE_UNKNOWN_PERMISSION'
  | 'EXCLUSIVE_STORE'
  | 'EXCLUSIVE_ERROR';

/** What the binding throws: an `Error` with a stable `code`. */
export interface BindingError extends Error {
  code: ErrorCode;
}

export interface Grant {
  id: string;
  subject: SubjectMatcher;
  permission: string;
  target: { kind: string; id?: string };
  effect: 'allow' | 'deny';
  scope?: { kind: string; id?: string };
  condition?: unknown;
  /** Milliseconds since the Unix epoch. The grant counts from this instant (inclusive). */
  validFrom?: number;
  /** Milliseconds since the Unix epoch. The grant stops counting at this instant (exclusive). */
  validUntil?: number;
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
  /** The grant is outside its `validFrom`/`validUntil` window at the context's `now`. */
  | { kind: 'outside_window' }
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
  /** Milliseconds since the Unix epoch, inclusive. */
  validFrom?: number;
  /** Milliseconds since the Unix epoch, exclusive. */
  validUntil?: number;
}

export interface Bypass {
  permission: string;
  resource: Resource;
}

/** Invariants `apply` and `applyTemplate` check, by `kind`. */
export type InvariantSpec =
  | { kind: 'catalog_conformance' }
  | { kind: 'no_self_management' }
  | { kind: 'require_permission'; permission: string; resource: Resource }
  | {
      kind: 'no_lockout';
      permissions: string[];
      members: Subject[];
      resource: Resource;
      /** The administrator role and the subjects that may receive it; makes a refusal carry a `suggestion`. */
      reserve?: { adminRole: RoleAssignment; subjects: Subject[] };
    }
  /** A permission is only held together with its `depends_on` ones. */
  | { kind: 'prerequisites' }
  /** Only whoever holds `manager` grants a non-delegable permission. */
  | { kind: 'non_delegable'; manager: string }
  /** Management-only permissions go only to the listed roles. */
  | { kind: 'management_only'; roles: string[] }
  /** The actor only grants what they hold, unless they hold the bypass. */
  | { kind: 'no_escalation'; bypass?: Bypass }
  | { kind: 'forbid'; subject: SubjectMatcher; permissions: string[] };

export interface ApplyInput {
  actor: Subject;
  current: Grant[];
  mutation:
    | { add: Grant }
    | { remove: { id: string } }
    | { assign_role: { subject: Subject; role: RoleAssignment } }
    | { revoke_role: { subject: Subject; role: RoleAssignment } };
  invariants?: InvariantSpec[];
  tuples?: unknown[];
  audit?: { level: AuditLevel; prevHash?: string };
  meta?: Record<string, unknown>;
  /** Instant the governance judges the actor's windows at, in ms UTC. Defaults to the system clock. */
  now?: number;
}

export interface TemplateGrant {
  id: string;
  permission: string;
  target: { kind: string; id?: string };
  effect?: 'allow' | 'deny';
  scope?: { kind: string; id?: string };
  condition?: unknown;
}

/** A versioned set of model grants; materializing it copies them, with no link back to the template. */
export interface RoleTemplate {
  id: string;
  version: number;
  grants: TemplateGrant[];
}

export interface MaterializeInput {
  template: RoleTemplate;
  subject: SubjectMatcher;
  scope?: { kind: string; id?: string };
  /** Materialized grant ids are `<idPrefix>:<template grant id>`. */
  idPrefix: string;
}

export interface Materialized {
  template: string;
  templateVersion: number;
  mutations: ApplyInput['mutation'][];
  meta: Record<string, unknown>;
}

export interface ApplyTemplateInput extends MaterializeInput {
  actor: Subject;
  current: Grant[];
  invariants?: InvariantSpec[];
  tuples?: unknown[];
  audit?: { level: AuditLevel; prevHash?: string };
  meta?: Record<string, unknown>;
  now?: number;
}

export interface ApplyTemplateResult {
  ok: boolean;
  grants?: Grant[];
  violations?: Violation[];
  /** One record per change when accepted; only the refusal when not. Nothing is written by the binding. */
  audits: Array<Record<string, unknown>>;
}

export type Violation = { invariant: string; message: string; suggestion?: Suggestion };

/** How a party reaches a permission. */
export type AccessVia =
  | { type: 'override'; name: string }
  | { type: 'grant'; grant_id: string }
  | { type: 'role'; grant_id: string; role: string }
  | { type: 'inherited_role'; grant_id: string; role: string; from: string }
  | { type: 'relation'; grant_id: string; relation: string; object: ObjectRef }
  | { type: 'nothing' }
  | { type: 'unknown' };

/** A party a query names. */
export type SubjectRef =
  | { type: 'user'; id: string }
  | { type: 'object'; kind: string; id: string }
  | { type: 'role'; id: string }
  | { type: 'principal'; name: string }
  | { type: 'userset'; object: ObjectRef; relation: string }
  | { type: 'wildcard'; kind: string }
  | { type: 'anyone' }
  | { type: 'unknown' };

/** Filter expression `list` returns, for the caller's own query language. */
export type FilterExpr =
  | { op: 'true' | 'false' | 'unknown' }
  | { op: 'within'; anchor: { kind: string; id?: string } }
  | { op: 'on_path'; selector: { kind: string; id?: string } }
  | { op: 'anchor_in'; kind: string; ids: string[] }
  | { op: 'attr_eq'; attr: string; value: unknown }
  | { op: 'residual'; index: number }
  | { op: 'not'; expr: FilterExpr }
  | { op: 'and' | 'or'; exprs: FilterExpr[] };

export type FilterShape =
  | { type: 'nothing' | 'unknown' }
  | { type: 'kind'; except: unknown[] }
  | { type: 'ids'; ids: string[] }
  | { type: 'within'; anchors: unknown[] }
  | { type: 'compound'; expr: FilterExpr };

/** What only the resource, not the filter, decides. Never counts as permission. */
export type FilterResidual =
  | { type: 'condition'; grant_id: string; condition: unknown }
  | { type: 'override'; name: string }
  | { type: 'strategy'; name: string }
  | { type: 'outside_layout'; grant_ids: string[] }
  | { type: 'unknown' };

export interface ListOptions {
  /** Path steps from the listed `kind` to the widest (`['document', 'project', 'org']`). */
  layout?: string[];
  /** Resources to evaluate against the filter, to get back the allowed ids. */
  resources?: Resource[];
}

export interface ListResult {
  kind: string;
  permission: string;
  exact: boolean;
  shape: FilterShape;
  expr: FilterExpr;
  residual: FilterResidual[];
  warnings: string[];
  /** Allowed ids of `options.resources`; `null` without them. */
  ids: string[] | null;
}

export interface WhoCanOnResult {
  permission: string;
  resource: Resource;
  entries: Array<{ subject: SubjectRef; via: AccessVia }>;
  /** Parties allowed, but denied when they act together with `with`. */
  except: Array<{ allowed: SubjectRef; with: SubjectRef }>;
}

export interface CheckForResult {
  subject: SubjectRef;
  allowed: boolean;
  decision: Decision;
  via: AccessVia;
  explanation: Explanation;
}

/** Ceilings of the reverse queries; what is missing keeps the default. Over the ceiling the query throws `QUERY_LIMIT_EXCEEDED`. */
export interface QueryLimits {
  maxParties?: number;
  maxDecisions?: number;
}

export interface Lease {
  resource: ObjectRef;
  holder: ObjectRef;
  priority: number;
  /** Milliseconds since the Unix epoch. */
  acquiredAt: number;
  /** Milliseconds since the Unix epoch; the lease is over at this instant. */
  expiresAt: number;
}

export type Acquisition =
  | { outcome: 'granted'; lease: Lease }
  /** `previous` is the lease taken from its holder, to warn them. */
  | { outcome: 'preempted'; lease: Lease; previous: Lease }
  | { outcome: 'busy'; holder: Lease };

export interface ExclusiveOptions {
  /** Ceiling of a lease's duration, in ms. */
  maxTtlMs?: number;
  /** Names of the hold and preempt permissions in the catalog. */
  permissions?: { hold: string; preempt: string };
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
  violations?: Violation[];
  audit?: Record<string, unknown> | null;
}

export declare class Context {
  constructor(init?: { grants?: Grant[]; tuples?: unknown[]; env?: Record<string, unknown>; now?: number | null; limits?: QueryLimits });
  setGrants(grants: Grant[]): void;
  addGrant(grant: Grant): void;
  removeGrant(id: string): boolean;
  grants(): Grant[];
  readonly size: number;
  addTuple(tuple: unknown): boolean;
  removeTuple(tuple: unknown): boolean;
  setEnv(env: Record<string, unknown>): void;
  loadCapabilities(set: CapabilitySet): Subject;
  /** The instant, in ms UTC, that validity windows and queries judge at. `null` clears it: without it the engine fails closed. */
  setNow(now: number | null): void;
  /** Ceilings of the reverse queries; `null` restores the defaults. */
  setLimits(limits: QueryLimits | null): void;
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
  /** The template's changes as plain data, with no link to the template; nothing is applied. */
  materialize(input: MaterializeInput): Materialized;
  /** Materializes and applies the batch through the governance, in `depends_on` order. */
  applyTemplate(input: ApplyTemplateInput): ApplyTemplateResult;
  /** The filter of what `subject` holds `permission` on, among `kind` resources. */
  list(context: Context, subject: Subject, permission: string, kind: string, options?: ListOptions): ListResult;
  /** Parties named by an allow grant of the permission, anywhere. */
  whoCan(context: Context, permission: string): SubjectRef[];
  /** Who holds the permission on the resource, and how. */
  whoCanOn(context: Context, permission: string, resource: Resource): WhoCanOnResult;
  /** What each party can do on the resource. */
  accessOf(context: Context, resource: Resource): Array<{ subject: SubjectRef; permissions: string[] }>;
  /** The decision for a named party; `subjects` are those the resolver knows. An unknown one throws `UNKNOWN_SUBJECT`. */
  checkFor(context: Context, subject: SubjectRef, permission: string, resource: Resource, subjects: Subject[]): CheckForResult;
}

/** In-memory exclusive ownership of resources, with priority and preemption. */
export declare class Exclusive {
  constructor(options?: ExclusiveOptions);
  /** Checks that the catalog declares both permissions; throws `EXCLUSIVE_UNKNOWN_PERMISSION`. */
  validate(engine: Engine): void;
  acquire(
    engine: Engine,
    context: Context,
    subject: Subject,
    resource: Resource,
    terms: { priority: number; ttlMs: number },
    now?: number,
  ): Acquisition;
  holder(resource: ObjectRef, now?: number): Lease | null;
  release(resource: ObjectRef, holder: ObjectRef, now?: number): Lease;
  renew(resource: ObjectRef, holder: ObjectRef, ttlMs: number, now?: number): Lease;
  /** Removes and returns the leases that ran out. */
  expire(now?: number): Lease[];
}

export interface Themis {
  Engine: typeof Engine;
  Context: typeof Context;
  Exclusive: typeof Exclusive;
  auditEstimate(level: AuditLevel, records: number): number;
  backend: 'native' | 'wasm';
}

export function load(options?: { backend?: 'auto' | 'native' | 'wasm'; wasm?: unknown }): Promise<Themis>;
