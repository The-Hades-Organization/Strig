// Kysely adapter: the `expr` of `engine.list(...)` as a `where` callback over an `ExpressionBuilder`. Kysely is not
// imported at run time: the builder arrives as the callback's argument.
import type { Expression, ExpressionBuilder, SqlBool } from 'kysely';
import { compileFilter } from './orm.js';
import type { Atom, Emitter, ListFilter, OrmAdapter, OrmFilter, OrmMapping } from './orm.js';

export { OrmFilterError, bounds } from './orm.js';
export type { Atom, Emitter, ListFilter, OrmAdapter, OrmErrorCode, OrmFilter, OrmMapping } from './orm.js';

/** Column references as Kysely takes them: `'id'`, `'document.project_id'`. */
export type KyselyMapping = OrmMapping<string>;

// The builder is typed loosely on purpose: the callback runs against whatever database type the caller has.
type Builder = ExpressionBuilder<any, any>;

/** What `where(...)` of a Kysely query takes. */
export type KyselyWhere = (eb: Builder) => Expression<SqlBool>;

const emitter: Emitter<string, KyselyWhere> = {
  constant: (value) => (eb) => eb(eb.lit(1), '=', eb.lit(value ? 1 : 0) as never),
  atom(atom: Atom<string>, negated: boolean): KyselyWhere {
    const { column } = atom;
    return (eb) => {
      const ref = column as never;
      if (!negated) {
        if (atom.op === 'present') return eb(ref, 'is not', null);
        return atom.op === 'eq' ? eb(ref, '=', atom.value as never) : eb(ref, 'in', atom.values as never);
      }
      if (atom.op === 'present') return eb(ref, 'is', null);
      return eb.or([eb(ref, 'is', null), atom.op === 'eq' ? eb(ref, '<>', atom.value as never) : eb(ref, 'not in', atom.values as never)]);
    };
  },
  and: (parts) => (eb) => eb.and(parts.map((part) => part(eb))),
  or: (parts) => (eb) => eb.or(parts.map((part) => part(eb))),
};

/**
 * Translates a listing into a Kysely condition: `db.selectFrom('document').where(filter.where)`. Every atom is total
 * over `NULL`, so a deny never drops a row it does not reach. Throws `OrmFilterError` when the mapping lacks a kind
 * or attribute the filter reads, or the filter has a node with no query form (before the query is built).
 */
export function toWhere<P extends string>(filter: ListFilter<P>, mapping: KyselyMapping): OrmFilter<KyselyWhere, P> {
  return compileFilter(filter, mapping, emitter);
}

export const kysely: OrmAdapter<KyselyWhere, string> = { toWhere: (filter, mapping) => toWhere(filter, mapping) };
