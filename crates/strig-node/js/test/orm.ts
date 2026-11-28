// ORM adapters (`/prisma`, `/drizzle`, `/kysely`): the object each one builds, the refusals, and an oracle over
// SQLite: for every scenario the rows the generated `where` selects are compared with the ids the engine resolves.
// SQLite runs through sql.js (WebAssembly), so the suite is the same on Node and Bun. `run.js` imports this file.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { drizzle as drizzleSqlJs } from 'drizzle-orm/sql-js';
import { sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { Kysely, SqliteDialect } from 'kysely';
import type { FilterExpr, Grant, Resource, Subject } from '../dist/index.js';
import { load, scopeFromString } from '../dist/node.js';
import { toWhere as drizzleWhere } from '../dist/drizzle.js';
import { toWhere as kyselyWhere } from '../dist/kysely.js';
import { OrmFilterError, toWhere as prismaWhere } from '../dist/prisma.js';
import type { ListFilter } from '../dist/prisma.js';

let failures = 0;
async function test(name: string, fn: () => unknown) {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failures += 1;
    process.exitCode = 1;
    console.log(`not ok - ${name}\n  ${error instanceof Error ? error.stack : error}`);
  }
}

type PermissionId = 'document.view' | 'document.edit';
const listing = (expr: FilterExpr, extra: Partial<ListFilter<PermissionId>> = {}): ListFilter<PermissionId> => ({
  kind: 'document',
  permission: 'document.view',
  expr,
  residual: [],
  ...extra,
});

// ---------------------------------------------------------------------------------------------
// Data: the rows live in SQLite (flat columns) and, for Prisma, in objects a small evaluator reads.
// ---------------------------------------------------------------------------------------------

interface Row {
  id: string;
  project_id: string | null;
  org_id: string | null;
  name: string;
  owner: string | null;
}
const ROWS: Row[] = [
  { id: 'd1', project_id: 'p1', org_id: 'o1', name: 'alpha', owner: 'ana' },
  { id: 'd2', project_id: 'p1', org_id: 'o1', name: 'beta', owner: 'bob' },
  { id: 'd3', project_id: 'p2', org_id: 'o1', name: 'alpine', owner: 'ana' },
  { id: 'd4', project_id: 'p3', org_id: 'o2', name: 'abc', owner: null },
  { id: 'd5', project_id: 'p3', org_id: 'o2', name: 'xyz', owner: 'bob' },
  { id: 'd6', project_id: null, org_id: 'o1', name: 'orphan', owner: 'ana' },
  { id: 'd7', project_id: null, org_id: null, name: 'loose', owner: null },
  { id: 'd8', project_id: 'p2', org_id: 'o1', name: 'abacus', owner: 'bob' },
];
const resourceOf = (row: Row): Resource => ({
  path: [{ kind: 'document', id: row.id }, ...(row.project_id ? [{ kind: 'project', id: row.project_id }] : []), ...(row.org_id ? [{ kind: 'org', id: row.org_id }] : [])],
  attrs: { name: row.name, ...(row.owner ? { owner: row.owner } : {}) },
});

const documents = sqliteTable('documents', {
  id: text('id').notNull(),
  projectId: text('project_id'),
  orgId: text('org_id'),
  name: text('name').notNull(),
  owner: text('owner'),
});
interface Database {
  documents: Row;
}

const requireCjs = createRequire(import.meta.url);
const initSqlJs = requireCjs('sql.js') as () => Promise<SqlJsStatic>;
interface SqlJsStatement {
  bind(values: unknown[]): boolean;
  step(): boolean;
  getAsObject(): Record<string, unknown>;
  free(): boolean;
}
interface SqlJsDatabase {
  run(sql: string, params?: unknown[]): void;
  prepare(sql: string): SqlJsStatement;
  getRowsModified(): number;
  close(): void;
}
interface SqlJsStatic {
  Database: new () => SqlJsDatabase;
}

const SQL = await initSqlJs();
const sqlite = new SQL.Database();
sqlite.run('CREATE TABLE documents (id TEXT NOT NULL, project_id TEXT, org_id TEXT, name TEXT NOT NULL, owner TEXT)');
for (const row of ROWS) sqlite.run('INSERT INTO documents VALUES (?, ?, ?, ?, ?)', [row.id, row.project_id, row.org_id, row.name, row.owner]);

// Kysely's SqliteDialect takes a better-sqlite3-shaped handle; this is that shape over sql.js.
const kyselyDb = new Kysely<Database>({
  dialect: new SqliteDialect({
    database: {
      close: () => sqlite.close(),
      prepare: (sql: string) => ({
        reader: /^\s*select/i.test(sql),
        all: (params: readonly unknown[]) => {
          const statement = sqlite.prepare(sql);
          statement.bind([...params]);
          const rows: Record<string, unknown>[] = [];
          while (statement.step()) rows.push(statement.getAsObject());
          statement.free();
          return rows;
        },
        run: (params: readonly unknown[]) => {
          sqlite.run(sql, [...params]);
          return { changes: sqlite.getRowsModified(), lastInsertRowid: 0 };
        },
        iterate: () => {
          throw new Error('not used');
        },
      }),
    } as never,
  }),
});
const drizzleDb = drizzleSqlJs(sqlite as never);

// ---------------------------------------------------------------------------------------------
// Prisma: an evaluator of the `where` shapes the adapter emits, with SQL's rules for NULL, over rows as Prisma
// would return them (`project` is a related object, or `null` when the foreign key is).
// ---------------------------------------------------------------------------------------------

interface PrismaRow {
  [field: string]: unknown;
}
function prismaValue(row: PrismaRow, path: string[]): unknown {
  let node: unknown = row;
  for (const part of path) {
    if (node === null || node === undefined) return undefined;
    node = (node as PrismaRow)[part];
  }
  return node;
}
/** `undefined` means "no value": a missing relation or a null field. */
function evalPrisma(where: Record<string, unknown>, row: PrismaRow, path: string[] = []): boolean {
  return Object.entries(where).every(([key, cond]) => {
    if (key === 'AND') return (cond as Record<string, unknown>[]).every((item) => evalPrisma(item, row, path));
    if (key === 'OR') return (cond as Record<string, unknown>[]).some((item) => evalPrisma(item, row, path));
    const here = [...path, key];
    const value = prismaValue(row, here);
    if (cond === null) return value === null || value === undefined;
    if (typeof cond !== 'object') return value !== null && value !== undefined && value === cond;
    const ops = cond as Record<string, unknown>;
    if ('is' in ops) return ops.is === null ? value === null || value === undefined : value !== null && value !== undefined;
    if ('not' in ops) return ops.not === null ? value !== null && value !== undefined : value !== null && value !== undefined && value !== ops.not;
    if ('in' in ops) return value !== null && value !== undefined && (ops.in as unknown[]).includes(value);
    if ('notIn' in ops) return value !== null && value !== undefined && !(ops.notIn as unknown[]).includes(value);
    // a nested object: the fields of a related model
    return evalPrisma(ops, row, here);
  });
}
const prismaRows = ROWS.map((row) => ({ id: row.id, projectId: row.project_id, orgId: row.org_id, name: row.name, owner: row.owner }));
const PRISMA_MAPPING = { kind: 'document', id: 'id', paths: { project: 'projectId', org: 'orgId' }, attrs: { owner: 'owner' } } as const;
const idsOfPrisma = (where: Record<string, unknown>) => prismaRows.filter((row) => evalPrisma(where, row)).map((row) => row.id);

const SQL_MAPPING_DRIZZLE = { kind: 'document', id: documents.id, paths: { project: documents.projectId, org: documents.orgId }, attrs: { owner: documents.owner } };
const SQL_MAPPING_KYSELY = { kind: 'document', id: 'id', paths: { project: 'project_id', org: 'org_id' }, attrs: { owner: 'owner' } };

const idsOfDrizzle = (where: ReturnType<typeof drizzleWhere>['where']) =>
  drizzleDb
    .select({ id: documents.id })
    .from(documents)
    .where(where)
    .all()
    .map((row: { id: string }) => row.id)
    .sort();
const idsOfKysely = async (where: ReturnType<typeof kyselyWhere>['where']) =>
  (await kyselyDb.selectFrom('documents').select('id').where(where).execute()).map((row) => row.id).sort();

async function everyAdapter(filter: ListFilter<PermissionId>) {
  const prisma = prismaWhere(filter, PRISMA_MAPPING);
  const drizzle = drizzleWhere(filter, SQL_MAPPING_DRIZZLE);
  const kysely = kyselyWhere(filter, SQL_MAPPING_KYSELY);
  const settled = (name: 'prisma' | 'drizzle' | 'kysely') => {
    const wrapped = { prisma, drizzle, kysely }[name];
    return wrapped.settled !== undefined;
  };
  return {
    where: {
      prisma: idsOfPrisma(prisma.where).sort(),
      drizzle: idsOfDrizzle(drizzle.where),
      kysely: await idsOfKysely(kysely.where),
    },
    settled: {
      prisma: prisma.settled ? idsOfPrisma(prisma.settled).sort() : null,
      drizzle: drizzle.settled ? idsOfDrizzle(drizzle.settled) : null,
      kysely: kysely.settled ? await idsOfKysely(kysely.settled) : null,
    },
    hasSettled: { prisma: settled('prisma'), drizzle: settled('drizzle'), kysely: settled('kysely') },
  };
}

// ---------------------------------------------------------------------------------------------
// Unit: the expression forms, hand-built.
// ---------------------------------------------------------------------------------------------

await test('orm: every form of the expression selects the same rows in the three adapters', async () => {
  const cases: Array<[string, FilterExpr, string[]]> = [
    ['true', { op: 'true' }, ROWS.map((r) => r.id)],
    ['false', { op: 'false' }, []],
    ['global step', { op: 'on_path', selector: { kind: 'global' } }, ROWS.map((r) => r.id)],
    ['step of a kind', { op: 'on_path', selector: { kind: 'project' } }, ['d1', 'd2', 'd3', 'd4', 'd5', 'd8']],
    ['step with an id', { op: 'on_path', selector: { kind: 'project', id: 'p1' } }, ['d1', 'd2']],
    ['within an anchor', { op: 'within', anchor: { kind: 'org', id: 'o1' } }, ['d1', 'd2', 'd3', 'd6', 'd8']],
    ['the listed kind by id', { op: 'on_path', selector: { kind: 'document', id: 'd4' } }, ['d4']],
    ['anchor_in', { op: 'anchor_in', kind: 'document', ids: ['d1', 'd7'] }, ['d1', 'd7']],
    ['empty anchor_in', { op: 'anchor_in', kind: 'document', ids: [] }, []],
    ['attribute', { op: 'attr_eq', attr: 'owner', value: 'ana' }, ['d1', 'd3', 'd6']],
    ['and', { op: 'and', exprs: [{ op: 'within', anchor: { kind: 'org', id: 'o1' } }, { op: 'attr_eq', attr: 'owner', value: 'bob' }] }, ['d2', 'd8']],
    ['or', { op: 'or', exprs: [{ op: 'on_path', selector: { kind: 'project', id: 'p1' } }, { op: 'on_path', selector: { kind: 'project', id: 'p3' } }] }, ['d1', 'd2', 'd4', 'd5']],
    ['empty and is true', { op: 'and', exprs: [] }, ROWS.map((r) => r.id)],
    ['empty or is false', { op: 'or', exprs: [] }, []],
  ];
  for (const [label, expr, expected] of cases) {
    const out = await everyAdapter(listing(expr));
    for (const adapter of ['prisma', 'drizzle', 'kysely'] as const) assert.deepEqual(out.where[adapter], expected, `${label} (${adapter})`);
  }
});

await test('orm: a negation keeps the rows whose column is NULL (a deny does not reach what has no such step)', async () => {
  const cases: Array<[string, FilterExpr, string[]]> = [
    ['not step with an id', { op: 'not', expr: { op: 'on_path', selector: { kind: 'project', id: 'p2' } } }, ['d1', 'd2', 'd4', 'd5', 'd6', 'd7']],
    ['not step of a kind', { op: 'not', expr: { op: 'on_path', selector: { kind: 'project' } } }, ['d6', 'd7']],
    ['not anchor_in', { op: 'not', expr: { op: 'anchor_in', kind: 'org', ids: ['o1'] } }, ['d4', 'd5', 'd7']],
    ['not attribute', { op: 'not', expr: { op: 'attr_eq', attr: 'owner', value: 'ana' } }, ['d2', 'd4', 'd5', 'd7', 'd8']],
    ['not not', { op: 'not', expr: { op: 'not', expr: { op: 'on_path', selector: { kind: 'org', id: 'o2' } } } }, ['d4', 'd5']],
    ['not empty anchor_in', { op: 'not', expr: { op: 'anchor_in', kind: 'org', ids: [] } }, ROWS.map((r) => r.id)],
    [
      'allow minus deny',
      { op: 'and', exprs: [{ op: 'within', anchor: { kind: 'org', id: 'o1' } }, { op: 'not', expr: { op: 'on_path', selector: { kind: 'project', id: 'p2' } } }] },
      ['d1', 'd2', 'd6'],
    ],
    [
      'de Morgan under not',
      { op: 'not', expr: { op: 'or', exprs: [{ op: 'on_path', selector: { kind: 'project', id: 'p1' } }, { op: 'on_path', selector: { kind: 'org', id: 'o2' } }] } },
      ['d3', 'd6', 'd7', 'd8'],
    ],
  ];
  for (const [label, expr, expected] of cases) {
    const out = await everyAdapter(listing(expr));
    for (const adapter of ['prisma', 'drizzle', 'kysely'] as const) assert.deepEqual(out.where[adapter], expected, `${label} (${adapter})`);
  }
});

await test('orm: a residue is false below and true above, in both directions under a negation', async () => {
  const residual = [{ type: 'override' as const, name: 'owner-only' }];
  const all = ROWS.map((r) => r.id);
  const open = await everyAdapter(listing({ op: 'residual', index: 0 }, { residual }));
  for (const adapter of ['prisma', 'drizzle', 'kysely'] as const) {
    assert.deepEqual(open.where[adapter], all, `where is the upper bound (${adapter})`);
    assert.deepEqual(open.settled[adapter], [], `settled is the lower bound (${adapter})`);
  }
  // an allow with a residual condition, minus a deny: the residue never widens `settled`
  const mixed: FilterExpr = {
    op: 'and',
    exprs: [{ op: 'or', exprs: [{ op: 'on_path', selector: { kind: 'org', id: 'o2' } }, { op: 'residual', index: 0 }] }, { op: 'not', expr: { op: 'on_path', selector: { kind: 'project', id: 'p2' } } }],
  };
  const out = await everyAdapter(listing(mixed, { residual }));
  for (const adapter of ['prisma', 'drizzle', 'kysely'] as const) {
    assert.deepEqual(out.where[adapter], ['d1', 'd2', 'd4', 'd5', 'd6', 'd7'], `where (${adapter})`);
    assert.deepEqual(out.settled[adapter], ['d4', 'd5'], `settled (${adapter})`);
  }
  // a residue under a deny: the deny only removes rows from `settled` when it is certain
  const denied = await everyAdapter(listing({ op: 'not', expr: { op: 'residual', index: 0 } }, { residual }));
  for (const adapter of ['prisma', 'drizzle', 'kysely'] as const) {
    assert.deepEqual(denied.where[adapter], all, `a residual deny leaves every row to check (${adapter})`);
    assert.deepEqual(denied.settled[adapter], [], `and settles none (${adapter})`);
  }
  // no residue: no `settled`
  const plain = await everyAdapter(listing({ op: 'true' }));
  assert.deepEqual(plain.hasSettled, { prisma: false, drizzle: false, kysely: false });
});

await test('orm: what the mapping cannot express is an error, never "all rows"', () => {
  const code = (expected: string) => (error: unknown) => {
    assert.ok(error instanceof OrmFilterError, `expected OrmFilterError, got ${String(error)}`);
    assert.equal(error.code, expected, error.message);
    return true;
  };
  const adapters = [
    (f: ListFilter<PermissionId>, drop?: 'paths' | 'attrs') => prismaWhere(f, { ...PRISMA_MAPPING, ...(drop ? { [drop]: {} } : {}) }),
    (f: ListFilter<PermissionId>, drop?: 'paths' | 'attrs') => drizzleWhere(f, { ...SQL_MAPPING_DRIZZLE, ...(drop ? { [drop]: {} } : {}) }),
    (f: ListFilter<PermissionId>, drop?: 'paths' | 'attrs') => kyselyWhere(f, { ...SQL_MAPPING_KYSELY, ...(drop ? { [drop]: {} } : {}) }),
  ];
  for (const toWhere of adapters) {
    assert.throws(() => toWhere(listing({ op: 'on_path', selector: { kind: 'project', id: 'p1' } }), 'paths'), code('UNMAPPED_KIND'));
    assert.throws(() => toWhere(listing({ op: 'anchor_in', kind: 'org', ids: ['o1'] }), 'paths'), code('UNMAPPED_KIND'));
    assert.throws(() => toWhere(listing({ op: 'anchor_in', kind: 'org', ids: [] }), 'paths'), code('UNMAPPED_KIND'), 'an empty set still names the kind');
    assert.throws(() => toWhere(listing({ op: 'not', expr: { op: 'attr_eq', attr: 'owner', value: 'a' } }), 'attrs'), code('UNMAPPED_ATTRIBUTE'));
    assert.throws(() => toWhere(listing({ op: 'attr_eq', attr: 'toString', value: 'a' })), code('UNMAPPED_ATTRIBUTE'), 'names are looked up as own keys only');
    assert.throws(() => toWhere(listing({ op: 'attr_eq', attr: 'owner', value: { nested: 1 } })), code('UNSUPPORTED_VALUE'));
    assert.throws(() => toWhere(listing({ op: 'unknown' })), code('UNSUPPORTED_EXPR'));
    assert.throws(() => toWhere(listing({ op: 'not', expr: { op: 'unknown' } })), code('UNSUPPORTED_EXPR'), 'an unknown node under a deny is not FALSE');
    assert.throws(() => toWhere(listing({ op: 'future_node' } as never)), code('UNSUPPORTED_EXPR'));
    assert.throws(() => toWhere(listing({ op: 'true' }, { kind: 'project' })), code('KIND_MISMATCH'));
  }
});

await test('orm: the id column answers for the listed kind, and a different kind needs its own column', async () => {
  const out = await everyAdapter(listing({ op: 'on_path', selector: { kind: 'document' } }));
  assert.deepEqual(out.where.drizzle, ROWS.map((r) => r.id));
});

await test('prisma: the shape of the object, with a relation path and an optional relation', () => {
  const nested = { kind: 'document', id: 'id', paths: { project: 'projectId', org: 'project.orgId' } };
  assert.deepEqual(prismaWhere(listing({ op: 'on_path', selector: { kind: 'org', id: 'o1' } }), nested).where, { project: { orgId: 'o1' } });
  assert.deepEqual(prismaWhere(listing({ op: 'anchor_in', kind: 'document', ids: ['d1'] }), nested).where, { id: { in: ['d1'] } });
  assert.deepEqual(prismaWhere(listing({ op: 'true' }), nested).where, {});
  assert.deepEqual(prismaWhere(listing({ op: 'false' }), nested).where, { OR: [] });

  const denied = listing({ op: 'not', expr: { op: 'on_path', selector: { kind: 'org', id: 'o1' } } });
  assert.deepEqual(
    prismaWhere(denied, nested).where,
    { OR: [{ project: { orgId: null } }, { project: { orgId: { not: 'o1' } } }] },
    'a required relation: only the field can be null',
  );
  assert.deepEqual(
    prismaWhere(denied, { ...nested, optionalRelations: ['project'] }).where,
    { OR: [{ project: { is: null } }, { project: { orgId: null } }, { project: { orgId: { not: 'o1' } } }] },
    'an optional relation: a row without it has no such step',
  );
  const open = prismaWhere(listing({ op: 'and', exprs: [{ op: 'true' }, { op: 'on_path', selector: { kind: 'project', id: 'p1' } }] }), nested);
  assert.deepEqual(open.where, { AND: [{}, { projectId: 'p1' }] });
});

await test('prisma: rows reached through an optional relation behave as the engine sees them', () => {
  const mapping = { kind: 'document', id: 'id', paths: { org: 'project.orgId' }, optionalRelations: ['project'] };
  const withProject = { id: 'a', project: { orgId: 'o1' } };
  const otherOrg = { id: 'b', project: { orgId: 'o2' } };
  const noOrg = { id: 'c', project: { orgId: null } };
  const noProject = { id: 'd', project: null };
  const run = (expr: FilterExpr) => [withProject, otherOrg, noOrg, noProject].filter((row) => evalPrisma(prismaWhere(listing(expr), mapping).where, row)).map((row) => row.id);
  assert.deepEqual(run({ op: 'on_path', selector: { kind: 'org', id: 'o1' } }), ['a']);
  assert.deepEqual(run({ op: 'on_path', selector: { kind: 'org' } }), ['a', 'b']);
  assert.deepEqual(run({ op: 'not', expr: { op: 'on_path', selector: { kind: 'org', id: 'o1' } } }), ['b', 'c', 'd']);
  assert.deepEqual(run({ op: 'not', expr: { op: 'on_path', selector: { kind: 'org' } } }), ['c', 'd']);
  assert.deepEqual(run({ op: 'not', expr: { op: 'anchor_in', kind: 'org', ids: ['o1', 'o2'] } }), ['c', 'd']);
});

await test('adapters share one contract: toWhere(filter, mapping) typed over the permission ids', async () => {
  const { prisma } = await import('../dist/prisma.js');
  const { drizzle } = await import('../dist/drizzle.js');
  const { kysely } = await import('../dist/kysely.js');
  const filter = listing({ op: 'true' });
  assert.equal(prisma.toWhere(filter, PRISMA_MAPPING).permission, 'document.view');
  assert.equal(drizzle.toWhere(filter, SQL_MAPPING_DRIZZLE).permission, 'document.view');
  assert.equal(kysely.toWhere(filter, SQL_MAPPING_KYSELY).permission, 'document.view');
  const narrowed: import('../dist/prisma.js').OrmAdapter<unknown, string, PermissionId> = prisma;
  // @ts-expect-error a permission outside the union does not type-check against an adapter narrowed to it
  narrowed.toWhere({ ...filter, permission: 'document.delete' }, PRISMA_MAPPING);
});

// ---------------------------------------------------------------------------------------------
// Oracle: engine.list resolves the ids; the generated where must agree.
// ---------------------------------------------------------------------------------------------

const SPEC = {
  catalog: {
    targetKinds: ['document'],
    broadTargets: ['project', 'org'],
    permissions: [
      { key: 'document.view', targets: ['document'] },
      { key: 'document.edit', targets: ['document'] },
    ],
  },
  roles: [],
};
const member = (id: string): Subject => ({ kind: 'user', id, roles: [{ role: 'member' }] });
const allow = (id: string, target: Grant['target'], scope?: Grant['scope'], extra: Partial<Grant> = {}): Grant => ({
  id,
  subject: { kind: 'role', id: 'member' },
  permission: 'document.view',
  target,
  effect: 'allow',
  ...(scope ? { scope } : {}),
  ...extra,
});
const deny = (id: string, target: Grant['target'], scope?: Grant['scope']): Grant => ({ ...allow(id, target, scope), effect: 'deny' });
const nameStartsWithA = { op: 'starts_with' as const, left: { attr: 'resource.name' }, right: 'a' };

const SCENARIOS: Array<[string, Grant[], string[] | 'residue']> = [
  ['nothing', [], []],
  ['the whole kind', [allow('g', { kind: 'document' })], ROWS.map((r) => r.id)],
  ['one org', [allow('g', { kind: 'document' }, { kind: 'org', id: 'o1' })], ['d1', 'd2', 'd3', 'd6', 'd8']],
  ['one project', [allow('g', { kind: 'document' }, { kind: 'project', id: 'p1' })], ['d1', 'd2']],
  ['an exact document', [allow('g', { kind: 'document', id: 'd4' })], ['d4']],
  ['an exact document and an org', [allow('g1', { kind: 'document', id: 'd4' }), allow('g2', { kind: 'document' }, { kind: 'org', id: 'o1' })], ['d1', 'd2', 'd3', 'd4', 'd6', 'd8']],
  ['the kind minus one project', [allow('g', { kind: 'document' }), deny('d', { kind: 'document' }, { kind: 'project', id: 'p2' })], ['d1', 'd2', 'd4', 'd5', 'd6', 'd7']],
  ['an org minus one project', [allow('g', { kind: 'document' }, { kind: 'org', id: 'o1' }), deny('d', { kind: 'document' }, { kind: 'project', id: 'p2' })], ['d1', 'd2', 'd6']],
  ['an org minus an exact document', [allow('g', { kind: 'document' }, { kind: 'org', id: 'o1' }), deny('d', { kind: 'document', id: 'd1' })], ['d2', 'd3', 'd6', 'd8']],
  ['a deny and nothing to allow', [deny('d', { kind: 'document' }, { kind: 'project', id: 'p2' })], []],
  ['a condition over the resource', [allow('g', { kind: 'document' }, { kind: 'org', id: 'o2' }, { condition: nameStartsWithA })], 'residue'],
  [
    'a condition and a plain allow',
    [allow('g1', { kind: 'document' }, { kind: 'org', id: 'o2' }, { condition: nameStartsWithA }), allow('g2', { kind: 'document' }, { kind: 'project', id: 'p1' })],
    'residue',
  ],
];

for (const backend of ['native', 'wasm'] as const) {
  const { Engine, Context } = await load({ backend });
  const engine = new Engine(SPEC);
  for (const [name, grants, expected] of SCENARIOS) {
    await test(`orm oracle (${backend}): ${name}`, async () => {
      const context = new Context({ grants });
      const result = engine.list(context, member('ana'), 'document.view', 'document', { layout: ['document', 'project', 'org'], resources: ROWS.map(resourceOf) });
      const resolved = [...(result.ids ?? [])].sort();
      if (expected !== 'residue') assert.deepEqual(resolved, expected, 'the scenario reads as the test says');
      const filter = result as ListFilter<PermissionId>;
      const out = await everyAdapter(filter);
      for (const adapter of ['prisma', 'drizzle', 'kysely'] as const) {
        const where = out.where[adapter];
        const settled = out.settled[adapter];
        for (const id of resolved) assert.ok(where.includes(id), `${adapter}: ${id} is allowed but the where leaves it out`);
        if (settled === null) {
          assert.deepEqual(where, resolved, `${adapter}: without a residue the where is exact`);
        } else {
          for (const id of settled) assert.ok(resolved.includes(id), `${adapter}: ${id} is in settled but the engine denies it`);
          assert.ok(result.residual.length > 0, 'a settled bound comes with its residue');
        }
      }
    });
  }
}

process.on('exit', () => {
  if (failures > 0) process.exitCode = 1;
});
