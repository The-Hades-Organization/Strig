// Prisma adapter: the `expr` of `engine.list(...)` as the `where` of a Prisma Client query. No Prisma import: the
// object is the plain `WhereInput` shape, so it works with any generated client and any Prisma major.
import { compileFilter, OrmFilterError } from './orm.js';
import type { Atom, Emitter, ListFilter, OrmAdapter, OrmFilter, OrmMapping } from './orm.js';

export { OrmFilterError, bounds } from './orm.js';
export type { Atom, Emitter, ListFilter, OrmAdapter, OrmErrorCode, OrmFilter, OrmMapping } from './orm.js';

/** A Prisma `where` object (`Prisma.<Model>WhereInput` accepts it). */
export type PrismaWhere = { [key: string]: unknown };

/**
 * Columns are model fields; a dotted path crosses to-one relations (`'project.orgId'`). A relation that can be absent
 * (an optional foreign key) is listed in `optionalRelations`: a row without it has no such step, which is what the
 * engine sees. A relation not listed is read as always present; then a row that lacks it is left out of a negated
 * condition, which is the cautious side (a deny drops it), never an allow.
 */
export interface PrismaMapping extends OrmMapping<string> {
  optionalRelations?: readonly string[];
}

/** Impossible condition: Prisma gives no rows for an empty `OR`. */
const NOTHING: PrismaWhere = { OR: [] };

function nest(path: readonly string[], leaf: unknown): PrismaWhere {
  let node: unknown = leaf;
  for (let i = path.length - 1; i >= 0; i -= 1) node = { [path[i] as string]: node };
  return node as PrismaWhere;
}

function emitter(optional: ReadonlySet<string>): Emitter<string, PrismaWhere> {
  const conjunction = (parts: PrismaWhere[]): PrismaWhere => (parts.length === 1 ? (parts[0] as PrismaWhere) : { AND: parts });
  const disjunction = (parts: PrismaWhere[]): PrismaWhere => (parts.length === 1 ? (parts[0] as PrismaWhere) : { OR: parts });

  /** Rows that have no value at the column: a missing optional relation on the way, or a null leaf. */
  const missing = (column: string): PrismaWhere[] => {
    const path = column.split('.');
    const out: PrismaWhere[] = [];
    path.slice(0, -1).forEach((relation, depth) => {
      if (optional.has(relation)) out.push(nest(path.slice(0, depth), { [relation]: { is: null } }));
    });
    out.push(nest(path, null));
    return out;
  };

  return {
    constant: (value) => (value ? {} : NOTHING),
    atom(atom: Atom<string>, negated: boolean): PrismaWhere {
      const path = atom.column.split('.');
      if (!negated) {
        const test = atom.op === 'present' ? { not: null } : atom.op === 'eq' ? atom.value : { in: atom.values };
        return nest(path, test);
      }
      const other = atom.op === 'present' ? [] : [nest(path, atom.op === 'eq' ? { not: atom.value } : { notIn: atom.values })];
      return disjunction([...missing(atom.column), ...other]);
    },
    and: conjunction,
    or: disjunction,
  };
}

/**
 * Translates a listing into a Prisma `where` for one model. Every atom is total over `null`, so a deny never
 * drops a row it does not reach. Throws {@link OrmFilterError} when the mapping lacks a kind or attribute the
 * filter reads, or the filter has a node with no query form.
 */
export function toWhere<P extends string>(filter: ListFilter<P>, mapping: PrismaMapping): OrmFilter<PrismaWhere, P> {
  return compileFilter(filter, mapping, emitter(new Set(mapping.optionalRelations ?? [])));
}

export const prisma: OrmAdapter<PrismaWhere, string> = { toWhere: (filter, mapping) => toWhere(filter, mapping) };
