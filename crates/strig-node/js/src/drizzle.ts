// Drizzle adapter: the `expr` of `engine.list(...)` as a drizzle-orm SQL expression over the columns of a table.
import type { AnyColumn, SQL } from 'drizzle-orm';
import { compileFilter } from './orm.js';
import type { Atom, Emitter, ListFilter, OrmAdapter, OrmFilter, OrmMapping } from './orm.js';
import { requirePeer } from './web-core.js';

export { OrmFilterError, bounds } from './orm.js';
export type { Atom, Emitter, ListFilter, OrmAdapter, OrmErrorCode, OrmFilter, OrmMapping } from './orm.js';

/** The columns of the table that holds the resources (`documents.id`, `documents.projectId`, ...). */
export type DrizzleMapping = OrmMapping<AnyColumn>;

type DrizzleOrm = typeof import('drizzle-orm');

// Loaded on first use, so importing this module does not need drizzle-orm until a filter is translated.
let orm: DrizzleOrm | undefined;
const peer = (): DrizzleOrm => (orm ??= requirePeer('drizzle-orm', 'drizzle') as DrizzleOrm);

function emitter(d: DrizzleOrm): Emitter<AnyColumn, SQL> {
  // `and`/`or` return `undefined` for no operands; the core never calls them with none.
  const all = (parts: SQL[]): SQL => d.and(...parts) as SQL;
  const any = (parts: SQL[]): SQL => d.or(...parts) as SQL;
  return {
    constant: (value) => (value ? d.sql`1 = 1` : d.sql`1 = 0`),
    atom(atom: Atom<AnyColumn>, negated: boolean): SQL {
      const { column } = atom;
      if (!negated) {
        if (atom.op === 'present') return d.isNotNull(column);
        return atom.op === 'eq' ? d.eq(column, atom.value) : d.inArray(column, atom.values);
      }
      if (atom.op === 'present') return d.isNull(column);
      return any([d.isNull(column), atom.op === 'eq' ? d.ne(column, atom.value) : d.notInArray(column, atom.values)]);
    },
    and: all,
    or: any,
  };
}

/**
 * Translates a listing into a Drizzle condition: `db.select().from(documents).where(filter.where)`. Every atom is
 * total over `NULL`, so a deny never drops a row it does not reach. Throws `OrmFilterError` when the mapping lacks
 * a kind or attribute the filter reads, or the filter has a node with no query form.
 */
export function toWhere<P extends string>(filter: ListFilter<P>, mapping: DrizzleMapping): OrmFilter<SQL, P> {
  return compileFilter(filter, mapping, emitter(peer()));
}

export const drizzle: OrmAdapter<SQL, AnyColumn> = { toWhere: (filter, mapping) => toWhere(filter, mapping) };
