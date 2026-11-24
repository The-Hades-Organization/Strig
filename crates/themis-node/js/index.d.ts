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

/**
 * Stable `code` of every error the binding throws (`error.code`), the same on both backends.
 * `INVALID_ARGUMENT` is a scalar argument that is not accepted (wrong type, `NaN`, `Infinity`, a
 * negative or fractional instant, a text where a number goes): it is never coerced. `INVALID_INPUT`
 * is a payload (an object) that does not have the expected shape. `EXCLUSIVE_ERROR` is what an
 * `Exclusive` failure without a code of its own falls into; today none does. `INTERNAL` is a result
 * that could not be turned into a JavaScript value; only the wasm backend reports it. A `Context`,
 * `Engine` or `Exclusive` argument of the wrong class fails in the native layer, before the binding.
 */
export type ErrorCode =
  | 'INVALID_ARGUMENT'
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
  | 'EXCLUSIVE_ERROR'
  | DslErrorCode
  | 'INTERNAL';

/** What the binding throws: an `Error` with a stable `code`. */
export interface BindingError extends Error {
  code: ErrorCode;
}

/** One side of a comparison: an attribute read at decision time (`subject.*`, `resource.*`, `env.*`) or a literal. */
export type ConditionOperand = { attr: string } | string | number | boolean | null | unknown[] | { [key: string]: unknown };

export type Weekday = 'mon' | 'tue' | 'wed' | 'thu' | 'fri' | 'sat' | 'sun';

/**
 * A condition stored with a grant. `time_between` and `weekday_in` read the decision instant
 * (`now` of the context) in UTC; without one they cannot be resolved, so a grant with them never allows.
 */
export type Condition =
  | { op: 'eq' | 'ne' | 'lt' | 'le' | 'gt' | 'ge'; left: ConditionOperand; right: ConditionOperand }
  | { op: 'in'; item: ConditionOperand; set: ConditionOperand }
  /** Text prefix. */
  | { op: 'starts_with'; left: ConditionOperand; right: ConditionOperand }
  /** Text suffix. */
  | { op: 'ends_with'; left: ConditionOperand; right: ConditionOperand }
  /** Substring when `left` is text; membership when `left` is a list. */
  | { op: 'contains'; left: ConditionOperand; right: ConditionOperand }
  /** The list `left` has at least one element of the list `right`. */
  | { op: 'any_in'; left: ConditionOperand; right: ConditionOperand }
  /** Every element of the list `left` is in the list `right` (an empty `left` holds). */
  | { op: 'all_in'; left: ConditionOperand; right: ConditionOperand }
  /** IPv4 or IPv6 address inside a CIDR, or inside any CIDR of a list. */
  | { op: 'ip_in'; item: ConditionOperand; set: ConditionOperand }
  /** UTC time of day in `[from, until)`, as `HH:MM`; `from` after `until` crosses midnight. */
  | { op: 'time_between'; from: string; until: string }
  /** UTC weekday of the decision instant. */
  | { op: 'weekday_in'; days: Weekday[] }
  | { op: 'exists'; attr: string }
  | { op: 'all' | 'any'; of: Condition[] }
  | { op: 'not'; cond: Condition }
  | { op: 'call'; func: string; args?: ConditionOperand[] };

export interface Grant {
  id: string;
  subject: SubjectMatcher;
  permission: string;
  target: { kind: string; id?: string };
  effect: 'allow' | 'deny';
  scope?: { kind: string; id?: string };
  condition?: Condition;
  /** Milliseconds since the Unix epoch. The grant counts from this instant (inclusive). */
  validFrom?: number;
  /** Milliseconds since the Unix epoch. The grant stops counting at this instant (exclusive). */
  validUntil?: number;
}

export type Reason =
  | { kind: 'override'; name: string }
  | { kind: 'grant'; grantId: string; permission: string; rank: number; strategy: string }
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
  /** Instant the governance judges the actor's windows at, in ms UTC. Defaults to the system clock; an invalid one (`NaN`, negative, text) throws `INVALID_ARGUMENT`, and a clock before 1970 is an error, never `0`. Never take it from a client: a past instant revives expired windows. */
  now?: number | bigint;
}

export interface TemplateGrant {
  id: string;
  permission: string;
  target: { kind: string; id?: string };
  effect?: 'allow' | 'deny';
  scope?: { kind: string; id?: string };
  condition?: Condition;
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
  now?: number | bigint;
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
  | { type: 'grant'; grantId: string }
  | { type: 'role'; grantId: string; role: string }
  | { type: 'inherited_role'; grantId: string; role: string; from: string }
  | { type: 'relation'; grantId: string; relation: string; object: ObjectRef }
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

/**
 * Filter expression `list` returns, for the caller's own query language. Treat `unknown` as
 * "check each row", never as `true`.
 */
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
  | { type: 'condition'; grantId: string; condition: Condition }
  | { type: 'override'; name: string }
  | { type: 'strategy'; name: string }
  | { type: 'outside_layout'; grantIds: string[] }
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
  | { kind: 'assign_role'; subjectId: string; role: RoleAssignment }
  | { kind: 'revoke_role'; subjectId: string; role: RoleAssignment };

export interface ApplyResult {
  ok: boolean;
  grants?: Grant[];
  /** Subject with the role applied, on an accepted role change. */
  subject?: Subject;
  violations?: Violation[];
  audit?: Record<string, unknown> | null;
}

export declare class Context {
  constructor(init?: { grants?: Grant[]; tuples?: unknown[]; env?: Record<string, unknown>; now?: number | bigint | null; limits?: QueryLimits });
  setGrants(grants: Grant[]): void;
  addGrant(grant: Grant): void;
  removeGrant(id: string): boolean;
  grants(): Grant[];
  readonly size: number;
  addTuple(tuple: unknown): boolean;
  removeTuple(tuple: unknown): boolean;
  setEnv(env: Record<string, unknown>): void;
  loadCapabilities(set: CapabilitySet): Subject;
  /**
   * The instant, in ms UTC, that validity windows and queries judge at. `null` or `undefined` clears
   * it: without it the engine fails closed. Anything that is not a non-negative integer up to 2^53
   * (`NaN`, `Infinity`, a text, a negative) throws `INVALID_ARGUMENT` and leaves the instant as it was.
   * The instant persists: a long-lived `Context` must be given `setNow` on every request, or pass
   * `now` to each call below, which wins over this one.
   */
  setNow(now: number | bigint | null): void;
  /** Ceilings of the reverse queries; `null` restores the defaults. */
  setLimits(limits: QueryLimits | null): void;
}

/**
 * Every method that decides or lists takes an optional trailing `now` (ms UTC) for that call, which
 * wins over the `Context` instant. The system clock is never used by these: without any `now` the
 * engine fails closed on windows.
 */
export declare class Engine {
  /** `EngineSpec` da Themis: catálogo, papéis, relações, estratégia, overrides. */
  constructor(spec: unknown);
  decide(context: Context, request: DecisionRequest, now?: number | bigint): Decision;
  check(context: Context, request: DecisionRequest, now?: number | bigint): boolean;
  /** A decisão com o rastro: overrides, destino de cada grant e árvore das condições. */
  explain(context: Context, request: DecisionRequest, now?: number | bigint): Explanation;
  capabilities(context: Context, subject: Subject, scope: Resource, now?: number | bigint): CapabilitySet;
  validateGrant(grant: Grant): void;
  catalog(): unknown;
  apply(input: ApplyInput): ApplyResult;
  /** The template's changes as plain data, with no link to the template; nothing is applied. */
  materialize(input: MaterializeInput): Materialized;
  /** Materializes and applies the batch through the governance, in `depends_on` order. */
  applyTemplate(input: ApplyTemplateInput): ApplyTemplateResult;
  /** The filter of what `subject` holds `permission` on, among `kind` resources. */
  list(context: Context, subject: Subject, permission: string, kind: string, options?: ListOptions, now?: number | bigint): ListResult;
  /** Parties named by an allow grant of the permission, anywhere. */
  whoCan(context: Context, permission: string, now?: number | bigint): SubjectRef[];
  /** Who holds the permission on the resource, and how. */
  whoCanOn(context: Context, permission: string, resource: Resource, now?: number | bigint): WhoCanOnResult;
  /** What each party can do on the resource. */
  accessOf(context: Context, resource: Resource, now?: number | bigint): Array<{ subject: SubjectRef; permissions: string[] }>;
  /** The decision for a named party; `subjects` are those the resolver knows. An unknown one throws `UNKNOWN_SUBJECT`. */
  checkFor(context: Context, subject: SubjectRef, permission: string, resource: Resource, subjects: Subject[], now?: number | bigint): CheckForResult;
}

/**
 * In-memory exclusive ownership of resources, with priority and preemption. `acquire` checks the
 * permissions at the `now` of the call, and so does `renew`: a holder who lost the permission cannot
 * keep the resource by renewing. `release` checks nothing, because giving the resource up is always
 * safe; the caller vouches for `holder`, so it must come from the server's own identity, never from a
 * client. Revoking a grant does not drop a lease that exists; it stops its renewal. A bad `now`
 * throws `INVALID_ARGUMENT`; the system clock is used only when `now` is omitted.
 */
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
    now?: number | bigint,
  ): Acquisition;
  holder(resource: ObjectRef, now?: number | bigint): Lease | null;
  release(resource: ObjectRef, holder: ObjectRef, now?: number | bigint): Lease;
  /** Extends the lease of `subject` to `now + ttlMs`, keeping its priority. Throws `EXCLUSIVE_DENIED` when the hold permission no longer holds at `now`. */
  renew(
    engine: Engine,
    context: Context,
    subject: Subject,
    resource: Resource,
    ttlMs: number,
    now?: number | bigint,
  ): Lease;
  /** Removes and returns the leases that ran out. */
  expire(now?: number | bigint): Lease[];
}

/** The syntaxes of the policy language. A source declares its own on the first line: `language rules`. */
export type PolicyLanguage = 'blocks' | 'rules' | 'actors';

/** Codes of the policy language, on top of `INVALID_ARGUMENT` (wrong type of argument, unknown language) and `INVALID_INPUT` (a policy object of the wrong shape). */
export type DslErrorCode =
  | 'DSL_PARSE'
  | 'DSL_VALIDATE'
  | 'DSL_CONFLICT'
  | 'DSL_UNREPRESENTABLE'
  | 'DSL_UNSUPPORTED'
  /** A size or count limit: too many sources, a source or the project too large, a directory with too many files. */
  | 'DSL_LIMIT'
  /** `loadProject` got the same `path` twice. */
  | 'DSL_DUPLICATE_SOURCE'
  /** `loadProjectDir` could not read the directory or a file, or found a `.themis` that is a link. The message carries the path and the system's error: do not pass it on to a remote client. */
  | 'DSL_IO';

/** Where the other side of a conflict lives. */
export interface DslPlace {
  file: string;
  line: number;
  column: number;
}

/** One problem, positioned. `file`, `line` and `column` are `null` for a policy that did not come from text. */
export interface DslDiagnostic {
  file: string | null;
  line: number | null;
  column: number | null;
  message: string;
  hint: string | null;
  /** Present on `DSL_CONFLICT`: the declaration this one clashes with. */
  related?: DslPlace;
}

/** What every language function throws: a stable `code` and at most 100 diagnostics, then one more saying "and N more errors not shown" when some were left out. */
export interface DslError extends Error {
  code: ErrorCode;
  diagnostics: DslDiagnostic[];
}

/** A policy in its canonical JSON: the same whatever the syntax it was written in. Comments are in `notes`. */
export interface PolicyPermission {
  key: string;
  targets: string[];
  label?: string;
  description?: string;
  impliedBy?: string[];
  dependsOn?: string[];
  nonDelegable?: boolean;
  managementOnly?: boolean;
  overrideOnly?: boolean;
  meta?: Record<string, unknown>;
}

export interface PolicyCatalog {
  targetKinds: string[];
  broadTargets: string[];
  permissions: PolicyPermission[];
}

export type PolicyStrategy = 'most_specific' | 'deny_overrides' | 'permit_overrides' | 'first_applicable';

export interface PolicyDocument {
  catalog: PolicyCatalog;
  roles?: unknown[];
  relations?: unknown[];
  strategy: PolicyStrategy;
  overrides?: unknown[];
  maxRelationDepth?: number;
  subjects?: unknown[];
  grants?: unknown[];
  tuples?: unknown[];
  invariants?: unknown[];
  notes?: PolicyNote[];
}

export interface PolicyNote {
  text: string;
  anchor: { element: string; placement: 'before' | 'after' | 'inline' | 'inside' };
  origin: { file: string; language: PolicyLanguage; line: number; column: number; field?: string };
}

export interface PolicySource {
  path: string;
  text: string;
}

export interface PolicyLanguageApi {
  /** Reads a source in the syntax it declares and validates it. `file` names it in the positions. Throws `DSL_PARSE` or `DSL_VALIDATE`. */
  compile(text: string, options?: { file?: string }): PolicyDocument;
  /** Writes a policy as text in `language`, comments included. Throws `DSL_UNREPRESENTABLE` when the syntax cannot say it. */
  print(policy: PolicyDocument, language: PolicyLanguage): string;
  /** Reads `text` in whatever syntax it declares and writes it in `language`. */
  convert(text: string, language: PolicyLanguage): string;
  /** Merges sources, each in its own syntax, into one policy. Throws `DSL_CONFLICT` with both positions when two declare the same thing, `DSL_DUPLICATE_SOURCE` for a repeated `path` and `DSL_LIMIT` past the size and count limits. */
  loadProject(sources: PolicySource[]): PolicyDocument;
}

export interface NativePolicyLanguageApi extends PolicyLanguageApi {
  /** Reads every `.themis` file of a directory as a project. Only the native module has it: the WebAssembly build has no IO. A `.themis` that is a link is refused with `DSL_IO`, never skipped. `dir` itself is resolved following links, so it must come from a trusted source, never from external input. */
  loadProjectDir(dir: string): PolicyDocument;
}

export interface Themis extends PolicyLanguageApi {
  Engine: typeof Engine;
  Context: typeof Context;
  Exclusive: typeof Exclusive;
  auditEstimate(level: AuditLevel, records: number): number;
  backend: 'native' | 'wasm';
}

export interface NativeThemis extends Themis, NativePolicyLanguageApi {
  backend: 'native';
}

export function load(options: { backend: 'native' }): Promise<NativeThemis>;
export function load(options?: { backend?: 'auto' | 'native' | 'wasm'; wasm?: unknown }): Promise<Themis>;
