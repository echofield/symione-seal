// The slice of the D1 API MANDATE uses, so tests can run the same Worker over node:sqlite (tests/d1.ts).

export interface Stmt {
  bind(...values: unknown[]): Stmt;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  run(): Promise<unknown>;
}

export interface Db {
  prepare(sql: string): Stmt;
  batch(statements: Stmt[]): Promise<unknown[]>;
}

// D1 refuses `undefined` and booleans; normalise once here.
const norm = (args: unknown[]) => args.map(a => (a === undefined ? null : typeof a === 'boolean' ? (a ? 1 : 0) : a));

export const stmt = (db: Db, sql: string, ...args: unknown[]) => db.prepare(sql).bind(...norm(args));
export const one = <T>(db: Db, sql: string, ...args: unknown[]) => stmt(db, sql, ...args).first<T>();
export const all = async <T>(db: Db, sql: string, ...args: unknown[]) => (await stmt(db, sql, ...args).all<T>()).results;
export const run = (db: Db, sql: string, ...args: unknown[]) => stmt(db, sql, ...args).run();

export const parse = <T>(json: string | null | undefined, fallback: T): T => {
  if (!json) return fallback;
  try { return JSON.parse(json) as T; } catch { return fallback; }
};
