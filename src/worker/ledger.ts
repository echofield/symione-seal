// Every state change and its ledger events commit in ONE D1 batch: either all land or none does.
// The event's sequence number is the primary key, so two concurrent writers cannot fork the chain: the second
// conflicts, re-reads the head and retries (pattern from MANDATE src/worker/audit.ts).
// A guarded transition is an UPDATE followed by `guard()`: if the UPDATE changed no row, the guard's CHECK fails and
// the whole batch rolls back, so the chain never records a transition that did not happen.

import { CHAIN_METHOD, nextEvent, verifyChain, type ChainEvent, type ChainHead } from '../core/chain';
import { redactValue } from '../core/redact';
import { all, one, stmt, type Db, type Stmt } from './db';
import { HttpError } from './http';

export interface EventInput { actor: string; action: string; runId: string; payload: unknown }

/** Place right after a guarded UPDATE in the same batch. */
export const guard = (db: Db) => stmt(db, 'INSERT INTO guards (ok) SELECT 0 WHERE changes() = 0');

// Only the guards table's named constraint means "the guarded UPDATE changed nothing"; any other CHECK failure is a
// real defect and must surface as a 500.
const isGuardFailure = (e: unknown) => /seal_guard/.test(e instanceof Error ? `${e.message} ${String((e as { cause?: unknown }).cause ?? '')}` : String(e));
const isChainConflict = (e: unknown) => /UNIQUE constraint failed: events\.|events\.seq|PRIMARY KEY/i.test(e instanceof Error ? e.message : String(e));

export async function commit(
  db: Db, now: () => string, newId: (p: string) => string,
  events: EventInput[], statements: Stmt[], conflict = { code: 'CONFLICT', message: 'The record changed while this request was in flight.' },
): Promise<ChainEvent[]> {
  for (let attempt = 0; ; attempt++) {
    let head = await one<ChainHead>(db, 'SELECT seq, hash, at FROM events ORDER BY seq DESC LIMIT 1');
    const built: ChainEvent[] = [];
    for (const e of events) {
      const ev = await nextEvent(head, { id: newId('evt'), at: now(), actor: e.actor, action: e.action, runId: e.runId, payload: redactValue(e.payload) });
      built.push(ev);
      head = { seq: ev.seq, hash: ev.hash, at: ev.at };
    }
    const inserts = built.map(ev => stmt(db,
      'INSERT INTO events (seq, id, at, actor, action, run_id, payload_json, payload_hash, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      ev.seq, ev.id, ev.at, ev.actor, ev.action, ev.runId, ev.payloadJson, ev.payloadHash, ev.prevHash, ev.hash));
    try {
      await db.batch([...statements, ...inserts]);
      return built;
    } catch (e) {
      if (isGuardFailure(e)) throw new HttpError(409, conflict.code, conflict.message);
      if (attempt < 4 && isChainConflict(e)) continue;
      throw e;
    }
  }
}

interface EventRow { seq: number; id: string; at: string; actor: string; action: string; run_id: string; payload_json: string; payload_hash: string; prev_hash: string; hash: string }
const toEvent = (r: EventRow): ChainEvent => ({
  seq: r.seq, id: r.id, at: r.at, actor: r.actor, action: r.action, runId: r.run_id,
  payloadJson: r.payload_json, payloadHash: r.payload_hash, prevHash: r.prev_hash, hash: r.hash,
});

export async function runEvents(db: Db, runId: string) {
  const rows = await all<EventRow>(db, 'SELECT * FROM events WHERE run_id = ? ORDER BY seq', runId);
  return rows.map(r => ({ seq: r.seq, at: r.at, actor: r.actor, action: r.action, payload: JSON.parse(r.payload_json) as unknown, hash: r.hash }));
}

export async function verifyLedger(db: Db) {
  const rows = await all<EventRow>(db, 'SELECT * FROM events ORDER BY seq');
  const events = rows.map(toEvent);
  const result = await verifyChain(events);
  const last = events.at(-1);
  return {
    intact: result.intact, count: events.length,
    head: last ? { seq: last.seq, hash: last.hash, at: last.at } : null,
    broken_at_seq: result.brokenAtSeq, reason: result.reason, method: CHAIN_METHOD,
  };
}
