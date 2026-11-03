// An in-memory SQLite database exposing the slice of the D1 API the Worker uses, with the real migrations applied.
// Pattern from city/src/lib/db/__tests__/sqlite-d1.ts (node:sqlite, BEGIN/COMMIT batch).
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Db, Stmt } from '../src/worker/db';

type Param = string | number | null;
const here = path.dirname(fileURLToPath(import.meta.url));

class SqliteStmt implements Stmt {
  constructor(private db: DatabaseSync, readonly sql: string, private params: Param[] = []) {}
  bind(...values: unknown[]): Stmt { return new SqliteStmt(this.db, this.sql, values as Param[]); }
  async first<T>(): Promise<T | null> { const r = this.db.prepare(this.sql).get(...this.params); return r ? ({ ...r } as T) : null; }
  async all<T>(): Promise<{ results: T[] }> { return { results: this.db.prepare(this.sql).all(...this.params).map(r => ({ ...r }) as T) }; }
  async run(): Promise<unknown> { return this.db.prepare(this.sql).run(...this.params); }
}

export function createTestDb(): Db & { raw: DatabaseSync } {
  const raw = new DatabaseSync(':memory:');
  raw.exec('PRAGMA foreign_keys = ON');
  const dir = path.resolve(here, '../migrations');
  for (const f of readdirSync(dir).filter(f => f.endsWith('.sql')).sort()) raw.exec(readFileSync(path.join(dir, f), 'utf8'));
  return {
    raw,
    prepare: (sql: string) => new SqliteStmt(raw, sql),
    async batch(statements: Stmt[]) {
      const out: unknown[] = [];
      raw.exec('BEGIN');
      try {
        for (const s of statements) {
          const sql = (s as SqliteStmt).sql;
          out.push(/^\s*(SELECT|WITH)\b|\bRETURNING\b/i.test(sql) ? await s.all() : await s.run());
        }
        raw.exec('COMMIT');
      } catch (e) { raw.exec('ROLLBACK'); throw e; }
      return out;
    },
  };
}
