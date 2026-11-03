// The Seal's ledger: one append-only sequence of events where each event's hash covers the previous one.
// Ported from MANDATE (src/core/chain.ts), single chain instead of one per tenant.
// Honest scope: tamper-EVIDENT, not tamper-proof, and the chain head is unsigned. A writer with database access can
// rewrite the whole chain; what it cannot do is change one past event without every later hash disagreeing.

import { canonical, digest, jsonSafe } from './canonical';

export const CHAIN_METHOD = 'SHA-256 hash chain over RFC 8785 canonical JSON; head unsigned';
export const GENESIS = 'sha256:genesis';

export interface ChainHead { seq: number; hash: string; at: string }

export interface ChainInput {
  id: string;
  at: string;
  actor: string;
  action: string;
  runId: string;
  payload: unknown;
}

export interface ChainEvent {
  seq: number;
  id: string;
  at: string;
  actor: string;
  action: string;
  runId: string;
  payloadJson: string;
  payloadHash: string;
  prevHash: string;
  hash: string;
}

function header(e: Omit<ChainEvent, 'hash' | 'payloadJson'>) {
  return {
    seq: e.seq, id: e.id, at: e.at, actor: e.actor, action: e.action, run_id: e.runId,
    payload_hash: e.payloadHash, prev_hash: e.prevHash,
  };
}

/** Builds the next event. Time never goes backwards: an event is stamped at the later of now and its predecessor. */
export async function nextEvent(head: ChainHead | null, input: ChainInput): Promise<ChainEvent> {
  const safe = jsonSafe(input.payload);
  const payloadJson = canonical(safe);
  const payloadHash = await digest(safe);
  const at = head && head.at > input.at ? head.at : input.at;
  const base = {
    seq: head ? head.seq + 1 : 0, id: input.id, at, actor: input.actor, action: input.action, runId: input.runId,
    payloadHash, prevHash: head ? head.hash : GENESIS,
  };
  return { ...base, payloadJson, hash: await digest(header(base)) };
}

/** Recomputes every link. Returns the first sequence number that does not reconcile. */
export async function verifyChain(events: ChainEvent[]): Promise<{ intact: boolean; brokenAtSeq: number | null; reason: string | null }> {
  const sorted = [...events].sort((a, b) => a.seq - b.seq);
  let prev: ChainEvent | null = null;
  for (const e of sorted) {
    const expectSeq = prev ? prev.seq + 1 : 0;
    if (e.seq !== expectSeq) return { intact: false, brokenAtSeq: e.seq, reason: `sequence gap: expected ${expectSeq}` };
    if (e.prevHash !== (prev ? prev.hash : GENESIS)) return { intact: false, brokenAtSeq: e.seq, reason: 'previous hash does not match' };
    if (prev && e.at < prev.at) return { intact: false, brokenAtSeq: e.seq, reason: 'time goes backwards' };
    let payload: unknown;
    try { payload = JSON.parse(e.payloadJson); } catch { return { intact: false, brokenAtSeq: e.seq, reason: 'payload is not JSON' }; }
    if (await digest(payload) !== e.payloadHash) return { intact: false, brokenAtSeq: e.seq, reason: 'payload hash does not match' };
    if (await digest(header(e)) !== e.hash) return { intact: false, brokenAtSeq: e.seq, reason: 'event hash does not match' };
    prev = e;
  }
  return { intact: true, brokenAtSeq: null, reason: null };
}
