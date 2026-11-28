// The logic of the inspector page, with no DOM: reading a scenario and a trail, asking the engine
// (WebAssembly) with the simulated grants, building the matrix and replaying audited decisions.
// Every verdict comes from the engine; nothing here decides access.
import type { ChainVerification, Context, Engine, Explanation, Grant, Strig, Subject } from '../crates/strig-node/js/dist/index.js';

export type Effect = 'allow' | 'deny';
export type Resource = Explanation['resource'];
export type Parsed<T> = { ok: true; value: T } | { ok: false; message: string };

/** The same JSON file `strig-inspect` reads. */
export interface Scenario {
  spec: Record<string, unknown>;
  grants: Grant[];
  tuples: unknown[];
  env: Record<string, unknown>;
  subjects: Record<string, Subject>;
  resources: Record<string, Resource>;
}

const SCENARIO_FIELDS = ['spec', 'grants', 'tuples', 'env', 'subjects', 'resources'];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const errorCode = (error: unknown): string | null => {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code : null;
};

const failure = (error: unknown): string => {
  const code = errorCode(error);
  const message = error instanceof Error ? error.message : String(error);
  return code === null ? message : `${message} (${code})`;
};

function jsonErrorAt(text: string, error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const at = /position (\d+)/.exec(message);
  if (!at) return `invalid JSON: ${message}`;
  const before = text.slice(0, Number(at[1]));
  const line = before.split('\n').length;
  const column = before.length - before.lastIndexOf('\n');
  return `invalid JSON at line ${line}, column ${column}: ${message}`;
}

function recordOf(value: unknown, field: string): Parsed<Record<string, unknown>> {
  if (value === undefined) return { ok: true, value: {} };
  return isRecord(value) ? { ok: true, value } : { ok: false, message: `\`${field}\` must be an object.` };
}

function listOf(value: unknown, field: string): Parsed<unknown[]> {
  if (value === undefined) return { ok: true, value: [] };
  return Array.isArray(value) ? { ok: true, value } : { ok: false, message: `\`${field}\` must be a list.` };
}

/** Reads a scenario like `strig-inspect` does: `spec` is required, unknown fields are refused. */
export function parseScenario(text: string): Parsed<Scenario> {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    return { ok: false, message: jsonErrorAt(text, error) };
  }
  if (!isRecord(raw)) return { ok: false, message: 'The scenario must be a JSON object.' };
  const unknown = Object.keys(raw).find((key) => !SCENARIO_FIELDS.includes(key));
  if (unknown !== undefined) return { ok: false, message: `Unknown field \`${unknown}\`; a scenario has ${SCENARIO_FIELDS.map((f) => `\`${f}\``).join(', ')}.` };
  if (!isRecord(raw.spec)) return { ok: false, message: 'The scenario needs a `spec` object: the policy.' };
  const grants = listOf(raw.grants, 'grants');
  if (!grants.ok) return grants;
  const tuples = listOf(raw.tuples, 'tuples');
  if (!tuples.ok) return tuples;
  const env = recordOf(raw.env, 'env');
  if (!env.ok) return env;
  const subjects = recordOf(raw.subjects, 'subjects');
  if (!subjects.ok) return subjects;
  const resources = recordOf(raw.resources, 'resources');
  if (!resources.ok) return resources;
  for (const [name, resource] of Object.entries(resources.value)) {
    if (!isRecord(resource) || !Array.isArray(resource.path)) return { ok: false, message: `The resource \`${name}\` needs a \`path\` list.` };
  }
  for (const [name, subject] of Object.entries(subjects.value)) {
    if (!isRecord(subject) || typeof subject.kind !== 'string') return { ok: false, message: `The subject \`${name}\` needs a \`kind\`.` };
  }
  return {
    ok: true,
    value: {
      spec: raw.spec,
      grants: grants.value as Grant[],
      tuples: tuples.value,
      env: env.value,
      subjects: subjects.value as Record<string, Subject>,
      resources: resources.value as Record<string, Resource>,
    },
  };
}

/** The effect of one question, asked with the simulated grants and again with the original ones. */
export interface Comparison {
  now: Explanation;
  /** The original answer; `null` while nothing is simulated. */
  before: Explanation | null;
  changed: boolean;
}

export interface Matrix {
  resource: string;
  permissions: string[];
  subjects: string[];
  /** `cells[permission][subject]` with the simulated grants. */
  cells: Effect[][];
  /** The same with the grants the scenario came with. */
  baseline: Effect[][];
}

export interface Change {
  permission: string;
  subject: string;
  before: Effect;
  after: Effect;
}

/** The cells the simulation turned over. */
export function matrixChanges(matrix: Matrix): Change[] {
  const changes: Change[] = [];
  matrix.cells.forEach((row, p) =>
    row.forEach((after, s) => {
      const before = matrix.baseline[p]?.[s];
      const permission = matrix.permissions[p];
      const subject = matrix.subjects[s];
      if (before !== undefined && before !== after && permission !== undefined && subject !== undefined) {
        changes.push({ permission, subject, before, after });
      }
    }),
  );
  return changes;
}

const ID = /^[A-Za-z0-9_.:-]{1,64}$/;

/** A scenario loaded into the engine, plus the grants switched off and the ones added to simulate. */
export class Session {
  private readonly disabled = new Set<string>();
  private added: Grant[] = [];

  private constructor(
    private readonly strig: Strig,
    readonly scenario: Scenario,
    readonly engine: Engine,
    readonly now: number,
  ) {}

  /** Builds the engine from `scenario.spec`; the engine's own message when the policy is not valid. */
  static open(strig: Strig, scenario: Scenario, now: number): Parsed<Session> {
    try {
      return { ok: true, value: new Session(strig, scenario, new strig.Engine(scenario.spec), now) };
    } catch (error) {
      if (errorCode(error) === null) throw error;
      return { ok: false, message: `The policy in \`spec\` was refused: ${failure(error)}` };
    }
  }

  permissions(): string[] {
    const catalog = this.scenario.spec.catalog;
    const list = isRecord(catalog) && Array.isArray(catalog.permissions) ? catalog.permissions : [];
    return list.flatMap((p) => (isRecord(p) && typeof p.key === 'string' ? [p.key] : []));
  }

  targetKinds(): string[] {
    const catalog = this.scenario.spec.catalog;
    if (!isRecord(catalog)) return [];
    const kinds = (field: string): string[] => (Array.isArray(catalog[field]) ? catalog[field].filter((k): k is string => typeof k === 'string') : []);
    return [...kinds('targetKinds'), ...kinds('broadTargets')];
  }

  roles(): string[] {
    const roles = this.scenario.spec.roles;
    return Array.isArray(roles) ? roles.flatMap((r) => (isRecord(r) && typeof r.role === 'string' ? [r.role] : [])) : [];
  }

  isEnabled(grantId: string): boolean {
    return !this.disabled.has(grantId);
  }

  toggle(grantId: string): void {
    if (!this.disabled.delete(grantId)) this.disabled.add(grantId);
  }

  addedGrants(): readonly Grant[] {
    return this.added;
  }

  /** Adds a grant to the simulation only. The engine validates it; a repeated id is refused. */
  add(grant: Grant): Parsed<Grant> {
    if (!ID.test(grant.id)) return { ok: false, message: 'The id takes letters, digits and `_ . : -`, up to 64.' };
    if (this.scenario.grants.some((g) => g.id === grant.id) || this.added.some((g) => g.id === grant.id)) {
      return { ok: false, message: `A grant \`${grant.id}\` already exists.` };
    }
    try {
      this.engine.validateGrant(grant);
    } catch (error) {
      if (errorCode(error) === null) throw error;
      return { ok: false, message: failure(error) };
    }
    this.added = [...this.added, grant];
    return { ok: true, value: grant };
  }

  removeAdded(grantId: string): void {
    this.added = this.added.filter((g) => g.id !== grantId);
  }

  reset(): void {
    this.disabled.clear();
    this.added = [];
  }

  isSimulating(): boolean {
    return this.disabled.size > 0 || this.added.length > 0;
  }

  /** The grants in force in the simulation. */
  activeGrants(): Grant[] {
    return [...this.scenario.grants.filter((g) => this.isEnabled(g.id)), ...this.added];
  }

  private context(grants: Grant[]): Context {
    return new this.strig.Context({ grants, tuples: this.scenario.tuples, env: this.scenario.env, now: this.now });
  }

  explain(subject: Subject, permission: string, resource: Resource, grants: Grant[] = this.activeGrants()): Explanation {
    return this.engine.explain(this.context(grants), { subject, permission, resource });
  }

  compare(subject: Subject, permission: string, resource: Resource): Comparison {
    const now = this.explain(subject, permission, resource);
    if (!this.isSimulating()) return { now, before: null, changed: false };
    const before = this.explain(subject, permission, resource, this.scenario.grants);
    return { now, before, changed: before.decision.effect !== now.decision.effect };
  }

  private decideAll(grants: Grant[], resource: Resource, permissions: string[], subjects: Subject[]): Effect[][] {
    const requests = permissions.flatMap((permission) => subjects.map((subject) => ({ subject, permission, resource })));
    const answers = requests.length === 0 ? [] : this.engine.checkMany(this.context(grants), requests);
    return permissions.map((_, p) => subjects.map((__, s) => (answers[p * subjects.length + s] === true ? 'allow' : 'deny')));
  }

  /** Every permission of the catalog for every subject of the scenario on one resource. */
  matrix(resourceName: string): Matrix {
    const resource = this.scenario.resources[resourceName];
    if (resource === undefined) throw new Error(`the scenario has no resource \`${resourceName}\``);
    const permissions = this.permissions();
    const names = Object.keys(this.scenario.subjects);
    const subjects = names.map((name) => this.scenario.subjects[name] as Subject);
    return {
      resource: resourceName,
      permissions,
      subjects: names,
      cells: this.decideAll(this.activeGrants(), resource, permissions, subjects),
      baseline: this.decideAll(this.scenario.grants, resource, permissions, subjects),
    };
  }
}

/* ───────── Audit trail ───────── */

export type TrailRecord = Record<string, unknown>;

export interface TrailProblem {
  line: number;
  message: string;
}

export interface Trail {
  records: TrailRecord[];
  /** The line of the file each record came from. */
  lines: number[];
  problems: TrailProblem[];
}

/** Reads JSON Lines: one record per line, blank lines skipped, a bad line reported by its number. */
export function parseTrail(text: string): Trail {
  const trail: Trail = { records: [], lines: [], problems: [] };
  text.split('\n').forEach((raw, i) => {
    if (raw.trim() === '') return;
    try {
      const record: unknown = JSON.parse(raw);
      if (!isRecord(record)) throw new Error('the line is not a JSON object');
      trail.records.push(record);
      trail.lines.push(i + 1);
    } catch (error) {
      trail.problems.push({ line: i + 1, message: error instanceof Error ? error.message : String(error) });
    }
  });
  return trail;
}

export type ChainStatus =
  | { kind: 'absent' }
  | { kind: 'intact'; records: number; head: string | null }
  | { kind: 'broken'; code: string; message: string; line: number | null };

/** Checks the hash chain of the `forensic` records, in file order. */
export function verifyTrail(strig: Strig, trail: Trail): ChainStatus {
  const forensic = trail.records.map((record, index) => ({ record, index })).filter((x) => x.record.level === 'forensic');
  if (forensic.length === 0) return { kind: 'absent' };
  const result: ChainVerification = strig.verifyAuditChain(forensic.map((x) => x.record));
  if (result.ok) return { kind: 'intact', records: forensic.length, head: result.head };
  const at = result.index === null ? undefined : forensic[result.index]?.index;
  return { kind: 'broken', code: result.code, message: result.message, line: at === undefined ? null : (trail.lines[at] ?? null) };
}

export type Replay =
  | { kind: 'replayed'; recorded: 'allowed' | 'denied'; explanation: Explanation; changed: boolean }
  | { kind: 'skipped'; reason: string };

const asRecord = (value: unknown): Record<string, unknown> | null => (isRecord(value) ? value : null);

/**
 * Asks the current policy the question an audited decision answered. A record needs `detailed` or
 * more (the subject and the resource in full); the others are skipped with the reason.
 */
export function replayRecord(session: Session, record: TrailRecord): Replay {
  if (record.action !== 'decision') return { kind: 'skipped', reason: 'not a decision' };
  const explained = asRecord(record.explanation);
  const subject = asRecord(record.actor_detail) ?? asRecord(explained?.subject);
  const resource = asRecord(record.resource) ?? asRecord(explained?.resource);
  const summary = asRecord(record.decision);
  const permission = typeof summary?.permission === 'string' ? summary.permission : explained?.permission;
  if (subject === null || resource === null || typeof permission !== 'string') {
    return { kind: 'skipped', reason: 'the record has no subject and resource in full (it needs level detailed or forensic)' };
  }
  const recorded = record.outcome === 'allowed' ? 'allowed' : 'denied';
  try {
    const explanation = session.explain(subject as unknown as Subject, permission, resource as unknown as Resource);
    return { kind: 'replayed', recorded, explanation, changed: (explanation.decision.effect === 'allow') !== (recorded === 'allowed') };
  } catch (error) {
    if (errorCode(error) === null) throw error;
    return { kind: 'skipped', reason: `the engine refused the question: ${failure(error)}` };
  }
}
