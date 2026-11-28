// Approval flow for a change to the grants: a change the policy marks as needing approval waits as a pending
// request that another actor approves or refuses. The engine (`propose`, `resolve`, `expire`) judges and audits
// each step; this file keeps the requests and chains the audit records. Browser-safe: it uses no `node:*`.
// Import it from `@the-hades-organization/strig/approvals`.
import type {
  ApplyInput,
  ApprovalRule,
  ElevateInput,
  ElevateResult,
  ElevationRequest,
  ElevationRule,
  ExpireInput,
  ExpireResult,
  Grant,
  ImpactOptions,
  InvariantSpec,
  PendingRequest,
  ProposeInput,
  ProposeResult,
  ResolveInput,
  ResolveResult,
  ReviewImpactInput,
  ReviewImpactResult,
  Subject,
} from './index.js';

export type PendingStoreErrorCode = 'PENDING_DUPLICATE' | 'PENDING_UNKNOWN' | 'PENDING_NOT_PENDING';

export class PendingStoreError extends Error {
  readonly code: PendingStoreErrorCode;

  constructor(code: PendingStoreErrorCode, message: string) {
    super(message);
    this.name = 'PendingStoreError';
    this.code = code;
  }
}

/** Where the requests are kept. `put` refuses a taken id; `update` refuses a request that is no longer pending. */
export interface PendingStore {
  get(id: string): Promise<PendingRequest | undefined> | PendingRequest | undefined;
  put(request: PendingRequest): Promise<void> | void;
  update(request: PendingRequest): Promise<void> | void;
  /** Every request, whatever its status, oldest first. */
  list(): Promise<PendingRequest[]> | PendingRequest[];
  /**
   * Rewrites a request whatever its status, keeping the decision: an elevation keeps its revocation and the closing of its
   * review this way. Needed by `Elevations`, not by `Approvals`.
   */
  annotate?(request: PendingRequest): Promise<void> | void;
}

/** The three calls of the engine the flow needs. `Engine` has them. */
export interface ApprovalEngine {
  propose(input: ProposeInput): ProposeResult;
  resolve(input: ResolveInput): ResolveResult;
  expire(input: ExpireInput): ExpireResult;
  /** Needed by `Approvals.reviewImpact`. `Engine` has it. */
  reviewImpact?(input: ReviewImpactInput): ReviewImpactResult;
}

export class MemoryPendingStore implements PendingStore {
  private readonly requests = new Map<string, PendingRequest>();

  get(id: string): PendingRequest | undefined {
    const found = this.requests.get(id);
    return found && structuredClone(found);
  }

  put(request: PendingRequest): void {
    if (this.requests.has(request.id)) throw new PendingStoreError('PENDING_DUPLICATE', `request "${request.id}" already exists`);
    this.requests.set(request.id, structuredClone(request));
  }

  update(request: PendingRequest): void {
    const stored = this.requests.get(request.id);
    if (!stored) throw new PendingStoreError('PENDING_UNKNOWN', `request "${request.id}" does not exist`);
    if (stored.status.state !== 'pending') throw new PendingStoreError('PENDING_NOT_PENDING', `request "${request.id}" is no longer pending`);
    this.requests.set(request.id, structuredClone(request));
  }

  annotate(request: PendingRequest): void {
    const stored = this.requests.get(request.id);
    if (!stored) throw new PendingStoreError('PENDING_UNKNOWN', `request "${request.id}" does not exist`);
    if (stored.status.state !== request.status.state) throw new PendingStoreError('PENDING_NOT_PENDING', `request "${request.id}" was decided differently`);
    this.requests.set(request.id, structuredClone(request));
  }

  list(): PendingRequest[] {
    return [...this.requests.values()].map((r) => structuredClone(r)).sort((a, b) => a.requestedAt - b.requestedAt || (a.id < b.id ? -1 : 1));
  }
}

export interface ApprovalsOptions {
  /** Which kinds of change wait for approval, and who approves them. Without a rule for a kind, it applies at once. */
  approval: ApprovalRule[];
  invariants?: InvariantSpec[];
  /** The audit of every step. `prevHash` starts the chain; the flow carries the head from one call to the next. */
  audit?: ApplyInput['audit'];
  /** Computes the impact of every change: `propose` keeps it in the request and the approval recomputes it over the grants then. */
  impact?: ImpactOptions;
  /** Makes the id of a request when `propose` is not given one. Default: `crypto.randomUUID()`. */
  newId?: () => string;
  /** The instant of a step, in ms UTC, when the call gives none. Default: the engine's clock. */
  now?: () => number;
}

export interface CallOptions {
  now?: number;
  meta?: Record<string, unknown>;
  tuples?: unknown[];
}

export interface ProposeOptions extends CallOptions {
  id?: string;
  expiresAt?: number;
}

export interface DecideOptions extends CallOptions {
  /** Runs after the engine accepts an approval and before the request is marked approved: persist the grants (and the roles) here. A throw leaves the request pending. */
  persist?: (result: Extract<ResolveResult, { ok: true }>) => Promise<void> | void;
}

export class Approvals {
  private head: string | undefined;

  constructor(
    private readonly engine: ApprovalEngine,
    readonly store: PendingStore,
    private readonly options: ApprovalsOptions,
  ) {
    this.head = options.audit?.prevHash;
  }

  /** Applies the change at once when its kind needs no approval; otherwise stores a pending request. */
  async propose(actor: Subject, mutation: ApplyInput['mutation'], current: Grant[], options: ProposeOptions = {}): Promise<ProposeResult> {
    const id = options.id ?? this.options.newId?.() ?? globalThis.crypto.randomUUID();
    if (await this.store.get(id)) throw new PendingStoreError('PENDING_DUPLICATE', `request "${id}" already exists`);
    const result = this.engine.propose({
      ...this.common(current, options),
      actor,
      mutation,
      id,
      ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
    });
    this.follow(result.audits);
    if (result.ok && !result.applied) await this.store.put(result.request);
    return result;
  }

  /** The requests still waiting at `now`: pending and not due. */
  async pending(now: number = this.clock()): Promise<PendingRequest[]> {
    return (await this.store.list()).filter((r) => r.status.state === 'pending' && !(r.expiresAt !== undefined && now >= r.expiresAt));
  }

  /** Approves `id`: the invariants judge the change again over `current` and only then it applies. The author never approves. */
  async approve(id: string, approver: Subject, current: Grant[], options: DecideOptions = {}): Promise<ResolveResult> {
    return this.decide(id, approver, 'approve', undefined, current, options);
  }

  /** Refuses `id` with a reason. */
  async reject(id: string, approver: Subject, reason: string, current: Grant[] = [], options: DecideOptions = {}): Promise<ResolveResult> {
    return this.decide(id, approver, 'reject', reason, current, options);
  }

  /** The impact of pending request `id` as it was proposed and as it would be over `current` now, for the approver. Nothing is recorded. */
  async reviewImpact(id: string, current: Grant[], options: CallOptions = {}): Promise<ReviewImpactResult> {
    const request = await this.store.get(id);
    if (!request) throw new PendingStoreError('PENDING_UNKNOWN', `request "${id}" does not exist`);
    if (!this.engine.reviewImpact) throw new TypeError('the engine has no reviewImpact');
    return this.engine.reviewImpact({ ...this.common(current, options), request });
  }

  /** Closes the pending requests whose expiry has come and returns them. */
  async expire(options: CallOptions = {}): Promise<ExpireResult> {
    const requests = (await this.store.list()).filter((r) => r.status.state === 'pending');
    const result = this.engine.expire({ ...this.common([], options), requests });
    this.follow(result.audits);
    for (const request of result.expired) await this.close(request);
    return result;
  }

  private async decide(
    id: string,
    approver: Subject,
    decision: 'approve' | 'reject',
    reason: string | undefined,
    current: Grant[],
    options: DecideOptions,
  ): Promise<ResolveResult> {
    const request = await this.store.get(id);
    if (!request) throw new PendingStoreError('PENDING_UNKNOWN', `request "${id}" does not exist`);
    const result = this.engine.resolve({
      ...this.common(current, options),
      request,
      approver,
      decision,
      ...(reason === undefined ? {} : { reason }),
    });
    this.follow(result.audits);
    if (result.ok) {
      if (options.persist) await options.persist(result);
      await this.close(result.request);
    } else if (result.code === 'EXPIRED') {
      await this.close(result.request);
    }
    return result;
  }

  // The store refuses a request that is no longer pending, so the new status goes in over the pending one.
  private async close(request: PendingRequest): Promise<void> {
    await this.store.update(request);
  }

  private common(current: Grant[], options: CallOptions) {
    const now = options.now ?? this.options.now?.();
    return {
      current,
      approval: this.options.approval,
      ...(this.options.invariants ? { invariants: this.options.invariants } : {}),
      ...(this.options.impact ? { impact: this.options.impact } : {}),
      ...(this.options.audit ? { audit: { ...this.options.audit, ...(this.head === undefined ? {} : { prevHash: this.head }) } } : {}),
      ...(options.meta ? { meta: options.meta } : {}),
      ...(options.tuples ? { tuples: options.tuples } : {}),
      ...(now === undefined ? {} : { now }),
    };
  }

  private follow(audits: Array<Record<string, unknown>>): void {
    const hash = audits.at(-1)?.hash;
    if (typeof hash === 'string') this.head = hash;
  }

  private clock(): number {
    return this.options.now?.() ?? Date.now();
  }
}

/** The one call of the engine the elevation flow needs. `Engine` has it. */
export interface ElevationEngine {
  elevate(input: ElevateInput): ElevateResult;
}

export interface ElevationsOptions {
  /** What can be elevated and how: maximum duration, approver permission, justification and break-glass. Without a rule, the request is refused. */
  elevation: ElevationRule[];
  invariants?: InvariantSpec[];
  /** The audit of every step. Break-glass needs `level: 'forensic'`; its record is written in `closed` mode whatever `failMode` says. */
  audit?: ApplyInput['audit'];
  impact?: ImpactOptions;
  now?: () => number;
}

export interface ElevationPersistOptions extends CallOptions {
  /** Runs after the engine accepts the step and before the store keeps it: persist the grants (and the roles) here. A throw leaves the store as it was. */
  persist?: (result: Extract<ElevateResult, { ok: true }>) => Promise<void> | void;
}

/**
 * Temporary elevation and break-glass over a `PendingStore` that has `annotate`. The window opens at the approval and
 * lasts the requested duration, never past the policy's maximum; the author never approves their own request; a
 * break-glass is in force at once, audited as `forensic`, and leaves a review that someone else closes.
 */
export class Elevations {
  private head: string | undefined;

  constructor(
    private readonly engine: ElevationEngine,
    readonly store: PendingStore,
    private readonly options: ElevationsOptions,
  ) {
    this.head = options.audit?.prevHash;
  }

  /** Asks for an elevation. A break-glass request that is accepted is already in force: `result.applied` is `true` and `persist` runs. */
  async request(request: ElevationRequest, current: Grant[], options: ElevationPersistOptions & { expiresAt?: number } = {}): Promise<ElevateResult> {
    if (await this.store.get(request.id)) throw new PendingStoreError('PENDING_DUPLICATE', `request "${request.id}" already exists`);
    const result = this.step({ op: 'request', elevationRequest: request, ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }) }, current, options);
    if (result.ok) {
      if (result.applied === true && options.persist) await options.persist(result);
      await this.store.put(result.request);
    }
    return result;
  }

  /** Approves `id`: the window opens now. The invariants judge the change again over `current`. */
  async approve(id: string, approver: Subject, current: Grant[], options: ElevationPersistOptions = {}): Promise<ElevateResult> {
    const request = await this.load(id);
    const result = this.step({ op: 'approve', request, by: approver }, current, options);
    if (result.ok) {
      if (options.persist) await options.persist(result);
      await this.requireStore().update(result.request);
    } else if (result.code === 'EXPIRED') {
      await this.requireStore().update(result.request);
    }
    return result;
  }

  async reject(id: string, approver: Subject, reason: string, current: Grant[], options: CallOptions = {}): Promise<ElevateResult> {
    const request = await this.load(id);
    const result = this.step({ op: 'reject', request, by: approver, reason }, current, options);
    if (result.ok) await this.requireStore().update(result.request);
    return result;
  }

  /** Takes an approved elevation back before its time: by the actor or by someone who holds the approver permission. `persist` removes the grant or the role. */
  async revoke(id: string, by: Subject, current: Grant[], options: ElevationPersistOptions & { reason?: string } = {}): Promise<ElevateResult> {
    const request = await this.load(id);
    const result = this.step({ op: 'revoke', request, by, ...(options.reason === undefined ? {} : { reason: options.reason }) }, current, options);
    if (result.ok) {
      if (options.persist) await options.persist(result);
      await this.annotate(result.request);
    }
    return result;
  }

  /** Closes the review of a break-glass with a note; the reviewer is someone other than the actor. */
  async closeReview(id: string, reviewer: Subject, note: string, current: Grant[], options: CallOptions = {}): Promise<ElevateResult> {
    const request = await this.load(id);
    const result = this.step({ op: 'close_review', request, by: reviewer, reason: note }, current, options);
    if (result.ok) await this.annotate(result.request);
    return result;
  }

  /** The elevations approved, not revoked and inside their window at `now`. */
  async active(now: number = this.clock()): Promise<PendingRequest[]> {
    return (await this.store.list()).filter((r) => {
      const info = r.elevation;
      return (
        info !== undefined &&
        r.status.state === 'approved' &&
        now >= r.status.at &&
        info.revoked === undefined &&
        info.validUntil !== undefined &&
        now < info.validUntil
      );
    });
  }

  /** The break-glass elevations nobody reviewed yet. */
  async pendingReviews(): Promise<PendingRequest[]> {
    return (await this.store.list()).filter((r) => r.elevation?.breakGlass === true && r.elevation.review?.state === 'pending');
  }

  private step(input: Pick<ElevateInput, 'op'> & Partial<ElevateInput>, current: Grant[], options: CallOptions): ElevateResult {
    const now = options.now ?? this.options.now?.();
    const result = this.engine.elevate({
      current,
      elevation: this.options.elevation,
      ...(this.options.invariants ? { invariants: this.options.invariants } : {}),
      ...(this.options.impact ? { impact: this.options.impact } : {}),
      ...(this.options.audit ? { audit: { ...this.options.audit, ...(this.head === undefined ? {} : { prevHash: this.head }) } } : {}),
      ...(options.meta ? { meta: options.meta } : {}),
      ...(options.tuples ? { tuples: options.tuples } : {}),
      ...(now === undefined ? {} : { now }),
      ...input,
    });
    const hash = result.audits.at(-1)?.hash;
    if (typeof hash === 'string') this.head = hash;
    return result;
  }

  private async load(id: string): Promise<PendingRequest> {
    const request = await this.store.get(id);
    if (!request) throw new PendingStoreError('PENDING_UNKNOWN', `request "${id}" does not exist`);
    return request;
  }

  private requireStore(): PendingStore {
    return this.store;
  }

  private async annotate(request: PendingRequest): Promise<void> {
    if (!this.store.annotate) throw new TypeError('the pending store has no annotate: an elevation needs it to keep a revocation or a review');
    await this.store.annotate(request);
  }

  private clock(): number {
    return this.options.now?.() ?? Date.now();
  }
}
