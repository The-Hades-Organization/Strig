// Shared core of the ORM adapters (`/prisma`, `/drizzle`, `/kysely`): turns the `expr` of `engine.list(...)` into
// the `where` of an ORM. It mirrors `PgTables` (`crates/strig-postgres/src/query.rs`): the same bounds over the
// residue, the same total atoms, the same refusals. Anything the mapping cannot express is an error, never "all rows".
import type { FilterExpr, FilterResidual } from './index.js';

/** The `GLOBAL` step of a path: every resource has it. */
const GLOBAL = 'global';

export type OrmErrorCode = 'UNMAPPED_KIND' | 'UNMAPPED_ATTRIBUTE' | 'UNSUPPORTED_EXPR' | 'KIND_MISMATCH' | 'UNSUPPORTED_VALUE';

/** Thrown when the filter cannot be expressed with the given mapping. The listing must not run. */
export class OrmFilterError extends Error {
  readonly code: OrmErrorCode;

  constructor(code: OrmErrorCode, message: string) {
    super(message);
    this.name = 'OrmFilterError';
    this.code = code;
  }
}

/**
 * Where the resources of a listing keep what a filter reads. `C` is the ORM's own column type (a field path for
 * Prisma, a `Column` for Drizzle, a column reference for Kysely).
 */
export interface OrmMapping<C> {
  /** The resource kind listed; the filter must be for the same kind. */
  kind: string;
  /** Column with the id of the listed resource. */
  id: C;
  /** Column with the id of each broader step of the path (`project` -> `projectId`). */
  paths?: Readonly<Record<string, C>>;
  /** Column with each resource attribute a rule reads (`owner` -> `ownerId`). */
  attrs?: Readonly<Record<string, C>>;
}

/** The part of a `list` result the adapters read. `P` narrows `permission` to the app's permission ids. */
export interface ListFilter<P extends string = string> {
  kind: string;
  permission: P;
  expr: FilterExpr;
  residual: FilterResidual[];
  exact?: boolean;
}

/** A listing as an ORM `where`. */
export interface OrmFilter<W, P extends string = string> {
  permission: P;
  /** Holds for every allowed row; it also admits the rows `residual` settles. */
  where: W;
  /**
   * Holds only for rows that are allowed whatever the residue says. Present only when there is a residue: the rows
   * of `where` outside `settled` are the ones to check one by one with the engine.
   */
  settled?: W;
  /** What the database cannot settle. */
  residual: FilterResidual[];
}

/** The contract every adapter implements. */
export interface OrmAdapter<W, C, P extends string = string> {
  toWhere<Q extends P>(filter: ListFilter<Q>, mapping: OrmMapping<C>): OrmFilter<W, Q>;
}

/** What an atom tests; always `TRUE` or `FALSE`, never `NULL`. */
export type Atom<C> =
  | { op: 'present'; column: C }
  | { op: 'eq'; column: C; value: string | number | boolean }
  | { op: 'in'; column: C; values: string[] };

/**
 * What an adapter provides. `atom(atom, negated)` receives the negation already pushed to the leaves (`NOT` over a
 * nullable column is `NULL` in SQL and drops rows a deny does not reach), so a leaf is built to be total either way.
 */
export interface Emitter<C, W> {
  constant(value: boolean): W;
  atom(atom: Atom<C>, negated: boolean): W;
  and(parts: W[]): W;
  or(parts: W[]): W;
}

/** Bounds when every residual part is unknown: `lower` holds only where `expr` certainly holds, `upper` wherever it may. */
export function bounds(expr: FilterExpr): [FilterExpr, FilterExpr] {
  switch (expr.op) {
    case 'residual':
      return [{ op: 'false' }, { op: 'true' }];
    case 'not': {
      const [lower, upper] = bounds(expr.expr);
      return [{ op: 'not', expr: upper }, { op: 'not', expr: lower }];
    }
    case 'and':
    case 'or': {
      const pairs = expr.exprs.map(bounds);
      return [
        { op: expr.op, exprs: pairs.map((p) => p[0]) },
        { op: expr.op, exprs: pairs.map((p) => p[1]) },
      ];
    }
    default:
      return [expr, expr];
  }
}

export function hasResidual(expr: FilterExpr): boolean {
  switch (expr.op) {
    case 'residual':
      return true;
    case 'not':
      return hasResidual(expr.expr);
    case 'and':
    case 'or':
      return expr.exprs.some(hasResidual);
    default:
      return false;
  }
}

function mapped<C>(table: Readonly<Record<string, C>> | undefined, key: string): C | undefined {
  return table !== undefined && Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

function columnOfKind<C>(mapping: OrmMapping<C>, kind: string): C {
  const column = kind === mapping.kind ? mapping.id : mapped(mapping.paths, kind);
  if (column === undefined) throw new OrmFilterError('UNMAPPED_KIND', `no column mapped for path kind ${JSON.stringify(kind)}`);
  return column;
}

function step<C, W>(mapping: OrmMapping<C>, emitter: Emitter<C, W>, kind: string, id: string | undefined, negated: boolean): W {
  if (kind === GLOBAL) return emitter.constant(!negated);
  const column = columnOfKind(mapping, kind);
  return id === undefined ? emitter.atom({ op: 'present', column }, negated) : emitter.atom({ op: 'eq', column, value: id }, negated);
}

function build<C, W>(expr: FilterExpr, mapping: OrmMapping<C>, emitter: Emitter<C, W>, negated: boolean): W {
  switch (expr.op) {
    case 'true':
      return emitter.constant(!negated);
    case 'false':
      return emitter.constant(negated);
    case 'within':
      return step(mapping, emitter, expr.anchor.kind, expr.anchor.id, negated);
    case 'on_path':
      return step(mapping, emitter, expr.selector.kind, expr.selector.id, negated);
    case 'anchor_in': {
      const column = columnOfKind(mapping, expr.kind);
      if (expr.ids.length === 0) return emitter.constant(negated);
      return emitter.atom({ op: 'in', column, values: [...expr.ids] }, negated);
    }
    case 'attr_eq': {
      const column = mapped(mapping.attrs, expr.attr);
      if (column === undefined) throw new OrmFilterError('UNMAPPED_ATTRIBUTE', `no column mapped for resource attribute ${JSON.stringify(expr.attr)}`);
      const value = expr.value;
      if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') {
        throw new OrmFilterError('UNSUPPORTED_VALUE', `attribute ${JSON.stringify(expr.attr)} is compared with a value that is not a string, number or boolean`);
      }
      return emitter.atom({ op: 'eq', column, value }, negated);
    }
    case 'not':
      return build(expr.expr, mapping, emitter, !negated);
    case 'and':
    case 'or': {
      if (expr.exprs.length === 0) return emitter.constant(expr.op === 'and' ? !negated : negated);
      const parts = expr.exprs.map((item) => build(item, mapping, emitter, negated));
      const conjunction = (expr.op === 'and') !== negated;
      return conjunction ? emitter.and(parts) : emitter.or(parts);
    }
    default:
      // `unknown` and any node a later version adds: reading it as FALSE could open access under a deny.
      throw new OrmFilterError('UNSUPPORTED_EXPR', `expression node ${JSON.stringify((expr as { op?: unknown }).op)} has no query form`);
  }
}

function assertKind(filter: { kind: string }, mapping: { kind: string }): void {
  if (filter.kind !== mapping.kind) {
    throw new OrmFilterError('KIND_MISMATCH', `the filter lists ${JSON.stringify(filter.kind)} but the mapping is for ${JSON.stringify(mapping.kind)}`);
  }
}

/** Builds the `where` (and `settled`, with a residue) of a filter with an adapter's emitter. */
export function compileFilter<C, W, P extends string>(filter: ListFilter<P>, mapping: OrmMapping<C>, emitter: Emitter<C, W>): OrmFilter<W, P> {
  assertKind(filter, mapping);
  const [lower, upper] = bounds(filter.expr);
  const where = build(upper, mapping, emitter, false);
  const out: OrmFilter<W, P> = { permission: filter.permission, where, residual: filter.residual };
  if (hasResidual(filter.expr)) out.settled = build(lower, mapping, emitter, false);
  return out;
}
