// The Seal's engine: open a run, walk it one action at a time, pause on sealed kinds, record the person's decision,
// issue single-use receipts, take reports with evidence. Revived from OP-CHORE's executePlan (cursor + pause +
// approvals) with the ledger, the guard and the receipts added.

import { canonical, digest, jsonSafe } from '../core/canonical';
import { LIMITS, describePolicy, isKind, riskOf, KINDS, type Kind, type Risk } from '../core/policy';
import { redact, redactValue } from '../core/redact';
import { checkReceipt, publicJwk, signReceipt, type ReceiptPayload } from '../core/receipt';
import { all, one, stmt, type Db } from './db';
import { HttpError } from './http';
import { commit, guard, runEvents, type EventInput } from './ledger';

export interface Ctx {
  db: Db;
  now: () => string;
  newId: (prefix: string) => string;
  origin: string;
  signingKey: () => Promise<CryptoKey>;
  signingJwk: () => string;
}

export interface RunRow {
  id: string; agent: string; intent: string; plan_json: string; stop_conditions_json: string;
  status: 'open' | 'waiting_seal' | 'completed' | 'stopped'; cursor: number; action_count: number;
  stop_reason: string | null; created_at: string; updated_at: string; ended_at: string | null;
}
export interface ActionRow {
  run_id: string; idx: number; kind: Kind; risk: Risk; summary: string; input_json: string; input_hash: string;
  status: 'planned' | 'cleared' | 'waiting_seal' | 'sealed' | 'refused' | 'expired' | 'done' | 'failed';
  evidence_json: string | null; reported_at: string | null;
}
export interface ApprovalRow {
  id: string; run_id: string; idx: number; status: 'waiting' | 'sealed' | 'refused' | 'expired';
  requested_at: string; expires_at: string; decided_at: string | null; decided_by: string | null; note: string | null;
}
interface ReceiptRow {
  id: string; approval_id: string; run_id: string; idx: number; kind: string; input_hash: string; token: string;
  issued_at: string; expires_at: string; redeemed_at: string | null; redeemed_by: string | null;
}

const bad = (code: string, message: string) => new HttpError(400, code, message);

/** Why a run stopped, in words an agent can relay. `refused` carries the person's own note instead. */
const STOP_NOTES: Record<string, string> = {
  expired: 'Nobody decided within 24 hours. Open a new run if it still matters.',
  receipt_expired: 'The receipt expired before it was used. Open a new run.',
  failed: 'The agent reported this action failed.',
  late: 'The action was reported done after its receipt expired; the run stopped instead of completing.',
  abandoned: 'The run had no activity for 24 hours.',
};
const RUN_IDLE_SECONDS = 24 * 3600;

/** `__proto__` would vanish from the hash and the display (a plain-object assignment drops it): refuse it outright. */
function refuseProtoKeys(v: unknown, field: string, depth = 0): void {
  if (depth > 64 || !v || typeof v !== 'object') return;
  if (Array.isArray(v)) { v.forEach(x => refuseProtoKeys(x, field, depth + 1)); return; }
  for (const [k, x] of Object.entries(v)) {
    if (k === '__proto__') throw bad('INVALID_FIELD', `${field} must not contain a "__proto__" member.`);
    refuseProtoKeys(x, field, depth + 1);
  }
}
const addSeconds = (iso: string, s: number) => new Date(Date.parse(iso) + s * 1000).toISOString();

function str(v: unknown, field: string, max: number, min = 1): string {
  if (typeof v !== 'string') throw bad('INVALID_FIELD', `${field} must be a string.`);
  const t = v.trim();
  if (t.length < min || t.length > max) throw bad('INVALID_FIELD', `${field} must be ${min}–${max} characters.`);
  if (!t.isWellFormed()) throw bad('INVALID_FIELD', `${field} has invalid Unicode.`);
  return t;
}
function strList(v: unknown, field: string, maxItems: number, maxChars: number): string[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || v.length > maxItems) throw bad('INVALID_FIELD', `${field} must be a list of at most ${maxItems} strings.`);
  return v.map((x, i) => str(x, `${field}[${i}]`, maxChars));
}
function plainObject(v: unknown, field: string): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw bad('INVALID_FIELD', `${field} must be a JSON object.`);
  return v as Record<string, unknown>;
}
function canonicalSize(v: unknown, field: string, max: number): string {
  refuseProtoKeys(v, field);
  let text: string;
  try { text = canonical(jsonSafe(v)); } catch (e) { throw bad('INVALID_FIELD', `${field} is not canonical JSON: ${(e as Error).message}.`); }
  if (new TextEncoder().encode(text).byteLength > max) throw new HttpError(413, 'TOO_LARGE', `${field} exceeds ${max} bytes.`);
  return text;
}

// ---------------------------------------------------------------------------------------------------------------
// Expiry: seal requests that outlive their window stop their run. Swept lazily on every engine entry point.

export async function sweepExpired(ctx: Ctx, runId?: string): Promise<void> {
  const now = ctx.now();
  const due = runId
    ? await all<ApprovalRow>(ctx.db, "SELECT * FROM approvals WHERE status = 'waiting' AND expires_at <= ? AND run_id = ?", now, runId)
    : await all<ApprovalRow>(ctx.db, "SELECT * FROM approvals WHERE status = 'waiting' AND expires_at <= ? ORDER BY expires_at LIMIT 20", now);
  for (const a of due) {
    try {
      await commit(ctx.db, ctx.now, ctx.newId, [
        { actor: 'seal', action: 'seal.expired', runId: a.run_id, payload: { approval_id: a.id, index: a.idx, expires_at: a.expires_at } },
        { actor: 'seal', action: 'run.stopped', runId: a.run_id, payload: { reason: 'expired', index: a.idx } },
      ], [
        stmt(ctx.db, "UPDATE approvals SET status = 'expired' WHERE id = ? AND status = 'waiting'", a.id), guard(ctx.db),
        stmt(ctx.db, "UPDATE actions SET status = 'expired' WHERE run_id = ? AND idx = ?", a.run_id, a.idx),
        stmt(ctx.db, "UPDATE runs SET status = 'stopped', stop_reason = 'expired', updated_at = ?, ended_at = ? WHERE id = ?", now, now, a.run_id),
      ]);
    } catch (e) {
      if (!(e instanceof HttpError && e.status === 409)) throw e; // decided in the meantime
    }
  }
  // Idle runs (open, no seal request waiting, nothing for 24 h) close, so abandoned runs never hold the cap forever.
  const idleBefore = addSeconds(now, -RUN_IDLE_SECONDS);
  const idle = runId
    ? await all<RunRow>(ctx.db, "SELECT * FROM runs WHERE status = 'open' AND updated_at <= ? AND id = ?", idleBefore, runId)
    : await all<RunRow>(ctx.db, "SELECT * FROM runs WHERE status = 'open' AND updated_at <= ? ORDER BY updated_at LIMIT 20", idleBefore);
  for (const r of idle) {
    try {
      await commit(ctx.db, ctx.now, ctx.newId, [
        { actor: 'seal', action: 'run.stopped', runId: r.id, payload: { reason: 'abandoned', index: r.cursor, idle_since: r.updated_at } },
      ], [
        stmt(ctx.db, "UPDATE runs SET status = 'stopped', stop_reason = 'abandoned', updated_at = ?, ended_at = ? WHERE id = ? AND status = 'open' AND updated_at = ?", now, now, r.id, r.updated_at), guard(ctx.db),
      ]);
    } catch (e) {
      if (!(e instanceof HttpError && e.status === 409)) throw e; // touched in the meantime
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------

export function policy() { return describePolicy(); }

export async function openRun(ctx: Ctx, raw: unknown) {
  const b = plainObject(raw, 'body');
  const agent = str(b.agent, 'agent', LIMITS.maxAgentChars);
  const intent = str(b.intent, 'intent', LIMITS.maxIntentChars);
  const plan = strList(b.plan, 'plan', LIMITS.maxPlanSteps, LIMITS.maxPlanStepChars);
  const stopConditions = strList(b.stop_conditions, 'stop_conditions', LIMITS.maxStopConditions, LIMITS.maxPlanStepChars);
  if (!Array.isArray(b.actions) || b.actions.length < 1 || b.actions.length > LIMITS.maxActions) {
    throw bad('INVALID_ACTIONS', `actions must hold 1–${LIMITS.maxActions} actions.`);
  }
  const actions = await Promise.all(b.actions.map(async (rawAction, index) => {
    const a = plainObject(rawAction, `actions[${index}]`);
    if (!isKind(a.kind)) {
      throw bad('UNKNOWN_KIND', `actions[${index}].kind ${JSON.stringify(a.kind)} is not in the policy. Known kinds: ${Object.keys(KINDS).join(', ')}.`);
    }
    const input = plainObject(a.input ?? {}, `actions[${index}].input`);
    const rawJson = canonicalSize(input, `actions[${index}].input`, LIMITS.maxInputBytes);
    const summary = str(a.summary, `actions[${index}].summary`, LIMITS.maxSummaryChars);
    const displayJson = canonical(jsonSafe(redactValue(input)));
    // The person seals what they read. A sealed action whose input or summary would be redacted cannot be shown in
    // full, so it is refused: pass secrets by reference (e.g. "env:STRIPE_KEY"), never inline.
    if (riskOf(a.kind) === 'sealed' && (displayJson !== rawJson || redact(summary) !== summary)) {
      throw bad('SECRET_IN_SEALED_INPUT', `actions[${index}] carries something that looks like a secret. A sealed action must be fully visible to the person; refer to secrets by name.`);
    }
    return { index, kind: a.kind, risk: riskOf(a.kind), summary, inputHash: await digest(jsonSafe(input)), displayJson };
  }));

  await sweepExpired(ctx);
  const id = ctx.newId('run');
  const now = ctx.now();
  const db = ctx.db;
  const statements = [
    stmt(db, `INSERT INTO runs (id, agent, intent, plan_json, stop_conditions_json, status, cursor, action_count, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, 'open', 0, ?, ?, ?)`,
      id, agent, redact(intent), JSON.stringify(plan.map(redact)), JSON.stringify(stopConditions.map(redact)), actions.length, now, now),
    // Refusal guard (RDE-Kernel): counted inside the same transaction, so two concurrent opens cannot both slip past.
    // The agent label is self-declared, so a total cap across labels stands behind the per-label one.
    stmt(db, `INSERT INTO guards (ok) SELECT 0 WHERE (SELECT COUNT(*) FROM runs WHERE agent = ? AND status IN ('open', 'waiting_seal')) > ?
              OR (SELECT COUNT(*) FROM runs WHERE status IN ('open', 'waiting_seal')) > ?`,
      agent, LIMITS.maxOpenRunsPerAgent, LIMITS.maxOpenRunsTotal),
    ...actions.map(a => stmt(db,
      "INSERT INTO actions (run_id, idx, kind, risk, summary, input_json, input_hash, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'planned')",
      id, a.index, a.kind, a.risk, redact(a.summary), a.displayJson, a.inputHash)),
  ];
  await commit(db, ctx.now, ctx.newId, [{
    actor: `agent:${agent}`, action: 'run.opened', runId: id,
    payload: { agent, intent, plan, stop_conditions: stopConditions, actions: actions.map(a => ({ index: a.index, kind: a.kind, risk: a.risk, summary: a.summary, input_hash: a.inputHash })) },
  }], statements, { code: 'TOO_MANY_OPEN_RUNS', message: `Too many open runs (at most ${LIMITS.maxOpenRunsPerAgent} per agent, ${LIMITS.maxOpenRunsTotal} in total). Finish one first; idle runs close after 24 hours.` });

  return {
    run_id: id, status: 'open' as const, cursor: 0,
    actions: actions.map(a => ({ index: a.index, kind: a.kind, risk: a.risk, status: 'planned' as const, input_hash: a.inputHash })),
    links: { run: `${ctx.origin}/runs/${id}` },
  };
}

async function loadRun(ctx: Ctx, runId: unknown): Promise<RunRow> {
  if (typeof runId !== 'string' || !/^run_[a-z0-9]{8,40}$/.test(runId)) throw new HttpError(404, 'NOT_FOUND', 'No such run.');
  const run = await one<RunRow>(ctx.db, 'SELECT * FROM runs WHERE id = ?', runId);
  if (!run) throw new HttpError(404, 'NOT_FOUND', 'No such run.');
  return run;
}
const loadAction = (ctx: Ctx, runId: string, idx: number) =>
  one<ActionRow>(ctx.db, 'SELECT * FROM actions WHERE run_id = ? AND idx = ?', runId, idx);

export async function next(ctx: Ctx, runId: unknown) {
  await sweepExpired(ctx, typeof runId === 'string' ? runId : undefined);
  const run = await loadRun(ctx, runId);
  const db = ctx.db;
  const now = ctx.now();
  // Stopped before done: a failed last action leaves the cursor on it, and the agent must hear "stop", never "done".
  if (run.status === 'stopped') {
    const reason = run.stop_reason ?? 'stopped';
    const approval = reason === 'refused'
      ? await one<ApprovalRow>(db, 'SELECT * FROM approvals WHERE run_id = ? AND idx = ?', run.id, run.cursor) : null;
    return { decision: 'stop' as const, index: run.cursor, reason, note: approval?.note ?? STOP_NOTES[reason] ?? null };
  }
  if (run.status === 'completed' || run.cursor >= run.action_count) return { decision: 'done' as const };
  const action = await loadAction(ctx, run.id, run.cursor);
  if (!action) throw new HttpError(500, 'INCONSISTENT', 'The run has no action at its cursor.');
  const base = { index: action.idx, kind: action.kind, input_hash: action.input_hash };

  if (action.status === 'cleared') return { decision: 'go' as const, ...base };
  if (action.status === 'planned' && action.risk !== 'sealed') {
    await commit(db, ctx.now, ctx.newId, [{ actor: 'seal', action: 'action.cleared', runId: run.id, payload: { index: action.idx, kind: action.kind, risk: action.risk } }], [
      stmt(db, "UPDATE actions SET status = 'cleared' WHERE run_id = ? AND idx = ? AND status = 'planned'", run.id, action.idx), guard(db),
      stmt(db, 'UPDATE runs SET updated_at = ? WHERE id = ?', now, run.id),
    ]).catch(async e => { if (!(e instanceof HttpError && e.status === 409)) throw e; });
    return { decision: 'go' as const, ...base };
  }
  if (action.status === 'planned' && action.risk === 'sealed') {
    const waiting = await one<{ n: number }>(db, "SELECT COUNT(*) AS n FROM approvals WHERE status = 'waiting'");
    if ((waiting?.n ?? 0) >= LIMITS.maxWaitingSeals) {
      throw new HttpError(429, 'TOO_MANY_WAITING', `${LIMITS.maxWaitingSeals} seal requests already wait for the person. Ask again once some are decided.`);
    }
    const approvalId = ctx.newId('seal');
    const expiresAt = addSeconds(now, LIMITS.sealRequestTtlSeconds);
    try {
      await commit(db, ctx.now, ctx.newId, [{
        actor: 'seal', action: 'seal.requested', runId: run.id,
        payload: { index: action.idx, kind: action.kind, approval_id: approvalId, input_hash: action.input_hash, expires_at: expiresAt },
      }], [
        stmt(db, "UPDATE actions SET status = 'waiting_seal' WHERE run_id = ? AND idx = ? AND status = 'planned'", run.id, action.idx), guard(db),
        stmt(db, "INSERT INTO approvals (id, run_id, idx, status, requested_at, expires_at) VALUES (?, ?, ?, 'waiting', ?, ?)", approvalId, run.id, action.idx, now, expiresAt),
        stmt(db, "UPDATE runs SET status = 'waiting_seal', updated_at = ? WHERE id = ?", now, run.id),
      ]);
    } catch (e) {
      if (!(e instanceof HttpError && e.status === 409)) throw e;
      return next(ctx, run.id); // a concurrent call opened the request first
    }
    return { decision: 'wait' as const, ...base, approval_id: approvalId, seal_url: `${ctx.origin}/seal/${approvalId}`, expires_at: expiresAt };
  }
  if (action.status === 'waiting_seal') {
    const a = await one<ApprovalRow>(db, 'SELECT * FROM approvals WHERE run_id = ? AND idx = ?', run.id, action.idx);
    if (!a) throw new HttpError(500, 'INCONSISTENT', 'Waiting action without a seal request.');
    return { decision: 'wait' as const, ...base, approval_id: a.id, seal_url: `${ctx.origin}/seal/${a.id}`, expires_at: a.expires_at };
  }
  if (action.status === 'sealed') {
    const r = await one<ReceiptRow>(db, 'SELECT * FROM receipts WHERE run_id = ? AND idx = ?', run.id, action.idx);
    if (!r) throw new HttpError(500, 'INCONSISTENT', 'Sealed action without a receipt.');
    if (!r.redeemed_at && r.expires_at <= now) {
      await commit(db, ctx.now, ctx.newId, [
        { actor: 'seal', action: 'run.stopped', runId: run.id, payload: { reason: 'receipt_expired', index: action.idx, receipt_id: r.id } },
      ], [
        stmt(db, "UPDATE actions SET status = 'expired' WHERE run_id = ? AND idx = ? AND status = 'sealed'", run.id, action.idx), guard(db),
        stmt(db, "UPDATE runs SET status = 'stopped', stop_reason = 'receipt_expired', updated_at = ?, ended_at = ? WHERE id = ?", now, now, run.id),
      ]).catch(e => { if (!(e instanceof HttpError && e.status === 409)) throw e; });
      return { decision: 'stop' as const, index: action.idx, reason: 'receipt_expired', note: 'The receipt expired before it was used. Open a new run.' };
    }
    return { decision: 'go' as const, ...base, receipt: r.token, receipt_id: r.id, receipt_expires_at: r.expires_at, receipt_redeemed: !!r.redeemed_at };
  }
  throw new HttpError(409, 'RUN_STATE', `The action at the cursor is ${action.status}.`);
}

export async function report(ctx: Ctx, runId: unknown, raw: unknown) {
  const b = plainObject(raw, 'body');
  const run = await loadRun(ctx, runId);
  const db = ctx.db;
  const now = ctx.now();
  if (run.status !== 'open') throw new HttpError(409, 'RUN_NOT_OPEN', `The run is ${run.status}.`);
  if (!Number.isSafeInteger(b.index) || b.index !== run.cursor) throw new HttpError(409, 'NOT_CURRENT', `Report the action at the cursor (${run.cursor}).`);
  if (b.outcome !== 'done' && b.outcome !== 'failed') throw bad('INVALID_FIELD', 'outcome must be "done" or "failed".');
  const action = await loadAction(ctx, run.id, run.cursor);
  if (!action) throw new HttpError(500, 'INCONSISTENT', 'The run has no action at its cursor.');
  if (action.status !== 'cleared' && action.status !== 'sealed') {
    throw new HttpError(409, 'ACTION_NOT_CLEARED', `The action is ${action.status}: ask next before acting, and wait for the seal on sealed kinds.`);
  }
  const evidence = b.evidence === undefined || b.evidence === null ? {} : plainObject(b.evidence, 'evidence');
  canonicalSize(evidence, 'evidence', LIMITS.maxEvidenceBytes);
  const sealed = action.risk === 'sealed';
  if (sealed && b.outcome === 'done' && Object.keys(evidence).length === 0) {
    throw bad('EVIDENCE_REQUIRED', 'A sealed action reported done needs evidence (a URL, a message id, a version id…).');
  }

  const events: EventInput[] = [];
  const statements = [
    stmt(db, "UPDATE actions SET status = ?, evidence_json = ?, reported_at = ? WHERE run_id = ? AND idx = ? AND status IN ('cleared', 'sealed')",
      b.outcome, canonical(jsonSafe(redactValue(evidence))), now, run.id, action.idx), guard(db),
  ];
  let receiptNote: Record<string, unknown> = {};
  let late = false;
  if (sealed) {
    const r = await one<ReceiptRow>(db, 'SELECT * FROM receipts WHERE run_id = ? AND idx = ?', run.id, action.idx);
    if (!r) throw new HttpError(500, 'INCONSISTENT', 'Sealed action without a receipt.');
    if (b.outcome === 'done') {
      if (typeof b.receipt !== 'string') throw bad('RECEIPT_REQUIRED', 'A sealed action reported done carries its receipt.');
      // Signature and binding only. A report after expiry is still RECORDED (the act may have happened), but the run
      // stops with reason "late" instead of completing: an expired seal never yields a completed run.
      const check = await checkReceipt(publicJwk(ctx.signingJwk()), b.receipt, action.input_hash, null);
      if (!check.ok || check.payload.receipt_id !== r.id) throw new HttpError(409, check.ok ? 'RECEIPT_MISMATCH' : check.code, check.ok ? 'This receipt belongs to another action.' : check.message);
    }
    if (!r.redeemed_at) {
      late = b.outcome === 'done' && r.expires_at <= now;
      statements.push(stmt(db, 'UPDATE receipts SET redeemed_at = ?, redeemed_by = ? WHERE id = ? AND redeemed_at IS NULL', now, `report:${b.outcome}`, r.id), guard(db));
      events.push({ actor: 'seal', action: 'receipt.redeemed', runId: run.id, payload: { receipt_id: r.id, index: action.idx, kind: action.kind, by: `report:${b.outcome}`, late } });
      receiptNote = { receipt_id: r.id, redeemed_by: `report:${b.outcome}`, late };
    } else {
      receiptNote = { receipt_id: r.id, redeemed_by: r.redeemed_by, redeemed_at: r.redeemed_at };
    }
  }
  events.push({ actor: `agent:${run.agent}`, action: b.outcome === 'done' ? 'action.done' : 'action.failed', runId: run.id, payload: { index: action.idx, kind: action.kind, evidence, ...receiptNote } });

  // The cursor moves only while the run goes on; a stop leaves it on the action that stopped it.
  const cursor = run.cursor + 1;
  let status: RunRow['status'] = 'open';
  if (b.outcome === 'failed' || late) {
    const reason = late ? 'late' : 'failed';
    status = 'stopped';
    statements.push(stmt(db, "UPDATE runs SET status = 'stopped', stop_reason = ?, updated_at = ?, ended_at = ? WHERE id = ?", reason, now, now, run.id));
    events.push({ actor: 'seal', action: 'run.stopped', runId: run.id, payload: { reason, index: action.idx } });
  } else if (cursor >= run.action_count) {
    status = 'completed';
    statements.push(stmt(db, "UPDATE runs SET status = 'completed', cursor = ?, updated_at = ?, ended_at = ? WHERE id = ?", cursor, now, now, run.id));
    events.push({ actor: 'seal', action: 'run.completed', runId: run.id, payload: { actions: run.action_count } });
  } else {
    statements.push(stmt(db, 'UPDATE runs SET cursor = ?, updated_at = ? WHERE id = ?', cursor, now, run.id));
  }
  await commit(db, ctx.now, ctx.newId, events, statements, {
    code: 'CONCURRENT_CHANGE',
    message: 'The action changed while this report was in flight (already reported, or its receipt redeemed at that moment). Check the run status, then retry if it is still at the cursor.',
  });
  return {
    run_id: run.id, status, cursor: status === 'stopped' ? run.cursor : cursor, late,
    next: status === 'completed' ? 'done' : status === 'stopped' ? 'stopped' : 'next',
  };
}

export async function decide(ctx: Ctx, approvalId: string, decision: 'seal' | 'refuse', noteRaw: unknown, decidedBy = 'operator') {
  const note = typeof noteRaw === 'string' && noteRaw.trim() ? str(noteRaw, 'note', LIMITS.maxNoteChars) : null;
  const approval = await one<ApprovalRow>(ctx.db, 'SELECT * FROM approvals WHERE id = ?', approvalId);
  if (!approval) throw new HttpError(404, 'NOT_FOUND', 'No such seal request.');
  await sweepExpired(ctx, approval.run_id);
  const db = ctx.db;
  const now = ctx.now();
  const action = await loadAction(ctx, approval.run_id, approval.idx);
  if (!action) throw new HttpError(500, 'INCONSISTENT', 'Seal request without an action.');
  const conflict = { code: 'ALREADY_DECIDED', message: 'This seal request is no longer waiting.' };
  const decideStmt = stmt(db,
    'UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, note = ? WHERE id = ? AND status = \'waiting\' AND expires_at > ?',
    decision === 'seal' ? 'sealed' : 'refused', now, decidedBy, note ? redact(note) : null, approval.id, now);

  if (decision === 'refuse') {
    await commit(db, ctx.now, ctx.newId, [
      { actor: decidedBy, action: 'seal.refused', runId: approval.run_id, payload: { approval_id: approval.id, index: approval.idx, kind: action.kind, note } },
      { actor: 'seal', action: 'run.stopped', runId: approval.run_id, payload: { reason: 'refused', index: approval.idx } },
    ], [
      decideStmt, guard(db),
      stmt(db, "UPDATE actions SET status = 'refused' WHERE run_id = ? AND idx = ?", approval.run_id, approval.idx),
      stmt(db, "UPDATE runs SET status = 'stopped', stop_reason = 'refused', updated_at = ?, ended_at = ? WHERE id = ?", now, now, approval.run_id),
    ], conflict);
    return { approval_id: approval.id, status: 'refused' as const };
  }

  const receiptId = ctx.newId('rcpt');
  const payload: ReceiptPayload = {
    v: 1, type: 'symione.seal.receipt', receipt_id: receiptId, run_id: approval.run_id, index: approval.idx, kind: action.kind,
    input_hash: action.input_hash, sealed_by: decidedBy, sealed_at: now, expires_at: addSeconds(now, LIMITS.receiptTtlSeconds), issuer: ctx.origin,
  };
  const token = await signReceipt(await ctx.signingKey(), payload);
  await commit(db, ctx.now, ctx.newId, [{
    actor: decidedBy, action: 'seal.granted', runId: approval.run_id,
    payload: { approval_id: approval.id, index: approval.idx, kind: action.kind, input_hash: action.input_hash, receipt_id: receiptId, receipt_expires_at: payload.expires_at, note },
  }], [
    decideStmt, guard(db),
    stmt(db, "UPDATE actions SET status = 'sealed' WHERE run_id = ? AND idx = ? AND status = 'waiting_seal'", approval.run_id, approval.idx), guard(db),
    stmt(db, 'INSERT INTO receipts (id, approval_id, run_id, idx, kind, input_hash, token, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      receiptId, approval.id, approval.run_id, approval.idx, action.kind, action.input_hash, token, now, payload.expires_at),
    stmt(db, "UPDATE runs SET status = 'open', updated_at = ? WHERE id = ? AND status = 'waiting_seal'", now, approval.run_id),
  ], conflict);
  return { approval_id: approval.id, status: 'sealed' as const, receipt_id: receiptId };
}

export async function redeem(ctx: Ctx, raw: unknown, by = 'downstream') {
  const b = plainObject(raw, 'body');
  if (typeof b.receipt !== 'string') throw bad('INVALID_FIELD', 'receipt must be a string.');
  if (typeof b.input_hash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(b.input_hash)) throw bad('INVALID_FIELD', 'input_hash must be sha256:<64 hex>.');
  // The downstream tool states what it is about to do: a receipt sealed for send_email never opens a deploy.
  if (!isKind(b.kind)) throw bad('INVALID_FIELD', 'kind must be the action kind the downstream tool is about to perform.');
  const now = ctx.now();
  const check = await checkReceipt(publicJwk(ctx.signingJwk()), b.receipt, b.input_hash, now);
  if (!check.ok) throw new HttpError(409, check.code, check.message);
  if (check.payload.kind !== b.kind) throw new HttpError(409, 'RECEIPT_MISMATCH', `The receipt was sealed for ${check.payload.kind}, not ${b.kind}.`);
  if (b.run_id !== undefined && b.run_id !== check.payload.run_id) throw new HttpError(409, 'RECEIPT_MISMATCH', 'The receipt belongs to another run.');
  const r = await one<ReceiptRow>(ctx.db, 'SELECT * FROM receipts WHERE id = ?', check.payload.receipt_id);
  if (!r || r.token !== b.receipt) throw new HttpError(409, 'RECEIPT_INVALID', 'This Seal did not issue that receipt.');
  await commit(ctx.db, ctx.now, ctx.newId, [{
    actor: by, action: 'receipt.redeemed', runId: r.run_id, payload: { receipt_id: r.id, index: r.idx, kind: r.kind, by, late: false },
  }], [
    stmt(ctx.db, 'UPDATE receipts SET redeemed_at = ?, redeemed_by = ? WHERE id = ? AND redeemed_at IS NULL AND expires_at > ?', now, by, r.id, now), guard(ctx.db),
  ], { code: 'RECEIPT_USED', message: 'This receipt was already used.' });
  return { ok: true, receipt_id: r.id, run_id: r.run_id, index: r.idx, kind: r.kind };
}

export async function status(ctx: Ctx, runId: unknown) {
  await sweepExpired(ctx, typeof runId === 'string' ? runId : undefined);
  const run = await loadRun(ctx, runId);
  const actions = await all<ActionRow>(ctx.db, 'SELECT * FROM actions WHERE run_id = ? ORDER BY idx', run.id);
  const approvals = await all<ApprovalRow>(ctx.db, 'SELECT * FROM approvals WHERE run_id = ? ORDER BY idx', run.id);
  const receipts = await all<ReceiptRow>(ctx.db, 'SELECT * FROM receipts WHERE run_id = ? ORDER BY idx', run.id);
  return {
    run: {
      id: run.id, agent: run.agent, intent: run.intent, plan: JSON.parse(run.plan_json) as string[],
      stop_conditions: JSON.parse(run.stop_conditions_json) as string[], status: run.status, cursor: run.cursor,
      stop_reason: run.stop_reason, created_at: run.created_at, ended_at: run.ended_at,
    },
    actions: actions.map(a => ({
      index: a.idx, kind: a.kind, risk: a.risk, summary: a.summary, status: a.status, input: JSON.parse(a.input_json) as unknown,
      input_hash: a.input_hash, evidence: a.evidence_json ? JSON.parse(a.evidence_json) as unknown : null, reported_at: a.reported_at,
    })),
    approvals: approvals.map(a => ({
      id: a.id, index: a.idx, status: a.status, requested_at: a.requested_at, expires_at: a.expires_at,
      decided_at: a.decided_at, decided_by: a.decided_by, note: a.note, seal_url: `${ctx.origin}/seal/${a.id}`,
    })),
    receipts: receipts.map(r => ({ id: r.id, index: r.idx, issued_at: r.issued_at, expires_at: r.expires_at, redeemed_at: r.redeemed_at, redeemed_by: r.redeemed_by })),
    events: await runEvents(ctx.db, run.id),
  };
}

export async function inbox(ctx: Ctx) {
  await sweepExpired(ctx);
  const waiting = await all<ApprovalRow & { kind: string; summary: string; intent: string; agent: string }>(ctx.db, `
    SELECT a.*, x.kind, x.summary, r.intent, r.agent FROM approvals a
    JOIN actions x ON x.run_id = a.run_id AND x.idx = a.idx JOIN runs r ON r.id = a.run_id
    WHERE a.status = 'waiting' ORDER BY a.requested_at`);
  const runs = await all<RunRow>(ctx.db, 'SELECT * FROM runs ORDER BY created_at DESC LIMIT 20');
  return { waiting, runs };
}

export async function sealView(ctx: Ctx, approvalId: string) {
  const approval = await one<ApprovalRow>(ctx.db, 'SELECT * FROM approvals WHERE id = ?', approvalId);
  if (!approval) throw new HttpError(404, 'NOT_FOUND', 'No such seal request.');
  const view = await status(ctx, approval.run_id);
  const fresh = await one<ApprovalRow>(ctx.db, 'SELECT * FROM approvals WHERE id = ?', approvalId);
  return { approval: fresh!, view };
}
