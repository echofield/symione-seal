#!/usr/bin/env node
// SYMIONE SEAL client — no dependencies, Node 20+.
//
//   SEAL_URL=https://… SEAL_AGENT_KEY=… node clients/seal.mjs <command>
//
//   run <kind> "<summary>" "<command line>" Ask for a seal, wait for the person, then run that exact command line
//                                          through the shell and report it. The sealed input is { command, cwd }: the
//                                          string the person reads is the string the shell receives.
//   gate <kind> "<summary>" <input.json>   Ask for a seal for one action and wait; prints the receipt JSON on go.
//   verify <kind> <receipt> <input.json>   Downstream check before acting: signature (offline, published key), the
//                                          kind you are about to perform, input hash, expiry, then redeem once online.
//                                          Exit 0 only if every check passes.
//   open <run.json> | next <run_id> | status <run_id> | report <run_id> <index> done|failed [evidence.json] [receipt]
//   hash <input.json> | policy | ledger
//
// Exit codes: 0 go/ok, 1 refused/stopped/failed check, 2 usage or configuration error, 3 timed out waiting.

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import process from 'node:process';

const BASE = (process.env.SEAL_URL ?? '').replace(/\/+$/, '');
const KEY = process.env.SEAL_AGENT_KEY ?? '';
const AGENT = process.env.SEAL_AGENT ?? `seal-cli@${process.env.COMPUTERNAME ?? process.env.HOSTNAME ?? 'local'}`;
const WAIT_SECONDS = Number(process.env.SEAL_WAIT_SECONDS ?? 1800);

const die = (msg, code = 2) => { console.error(msg); process.exit(code); };
const readJsonFile = p => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch (e) { die(`Cannot read JSON from ${p}: ${e.message}`); } };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// --- Canonical JSON + SHA-256, byte-identical to the Worker (src/core/canonical.ts) ----------------------------------
function canonical(value, depth = 0) {
  if (depth > 64) throw new Error('JSON nesting exceeds 64');
  if (value === null || typeof value === 'boolean') return String(value);
  if (typeof value === 'string') { if (!value.isWellFormed()) throw new Error('invalid Unicode'); return JSON.stringify(value); }
  if (typeof value === 'number') { if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error('only safe integers'); return String(value); }
  if (Array.isArray(value)) return '[' + value.map(v => canonical(v, depth + 1)).join(',') + ']';
  if (typeof value !== 'object') throw new Error('not a JSON value');
  return '{' + Object.keys(value).filter(k => value[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k], depth + 1)).join(',') + '}';
}
function jsonSafe(value) {
  if (value === undefined) return null;
  if (typeof value === 'number') return Number.isSafeInteger(value) && !Object.is(value, -0) ? value : String(value);
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value && typeof value === 'object') { const o = {}; for (const [k, v] of Object.entries(value)) if (v !== undefined) Object.defineProperty(o, k, { value: jsonSafe(v), enumerable: true, writable: true, configurable: true }); return o; }
  return value;
}
async function inputHash(input) {
  const bytes = new TextEncoder().encode(canonical(jsonSafe(input)));
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return 'sha256:' + [...d].map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- HTTP -------------------------------------------------------------------------------------------------------
function needConfig() {
  if (!/^https?:\/\//.test(BASE)) die('Set SEAL_URL (e.g. https://symione-seal.<account>.workers.dev).');
  if (!KEY) die('Set SEAL_AGENT_KEY.');
}
async function api(method, path, body) {
  needConfig();
  const res = await fetch(BASE + path, {
    method, headers: { authorization: `Bearer ${KEY}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { const err = new Error(data?.error?.message ?? `HTTP ${res.status}`); err.code = data?.error?.code; err.status = res.status; throw err; }
  return data;
}
const print = v => console.log(JSON.stringify(v, null, 2));

// --- Offline receipt check (published Ed25519 key) ----------------------------------------------------------------
const fromB64url = s => Uint8Array.from(Buffer.from(s, 'base64url'));
async function verifyReceipt(kind, token, input) {
  needConfig();
  const wk = await (await fetch(`${BASE}/.well-known/symione-seal.json`)).json();
  const [body, sig] = String(token).split('.');
  if (!body || !sig) return { ok: false, why: 'not a receipt token' };
  const key = await crypto.subtle.importKey('jwk', wk.public_key_jwk, { name: 'Ed25519' }, false, ['verify']);
  const bytes = fromB64url(body);
  if (!(await crypto.subtle.verify({ name: 'Ed25519' }, key, fromB64url(sig), bytes))) return { ok: false, why: 'signature does not verify against the published key' };
  const payload = JSON.parse(new TextDecoder().decode(bytes));
  if (payload.issuer !== wk.issuer) return { ok: false, why: `issued by ${payload.issuer}, expected ${wk.issuer}` };
  if (payload.kind !== kind) return { ok: false, why: `sealed for ${payload.kind}, not ${kind}` };
  const hash = await inputHash(input);
  if (payload.input_hash !== hash) return { ok: false, why: 'sealed for a different input' };
  if (!(new Date().toISOString() < payload.expires_at)) return { ok: false, why: 'expired' };
  try {
    await api('POST', '/api/receipts/redeem', { receipt: token, input_hash: hash, kind });
  } catch (e) { return { ok: false, why: `${e.code ?? 'redeem failed'}: ${e.message}` }; }
  return { ok: true, payload };
}

// --- Waiting for the person ---------------------------------------------------------------------------------------
async function waitForDecision(runId) {
  const deadline = Date.now() + WAIT_SECONDS * 1000;
  let shown = false;
  for (;;) {
    const n = await api('POST', `/api/runs/${runId}/next`, {});
    if (n.decision === 'go') return n;
    if (n.decision === 'stop' || n.decision === 'done') return n;
    if (!shown) { console.error(`\nWaiting for the seal → ${n.seal_url}\n(expires ${n.expires_at})`); shown = true; }
    if (Date.now() > deadline) { console.error('Still waiting; stopped polling. Run "next" later.'); process.exit(3); }
    await sleep(5000);
  }
}

async function gate(kind, summary, input, intent) {
  const run = await api('POST', '/api/runs', {
    agent: AGENT, intent: intent ?? summary, plan: [summary], stop_conditions: ['the person refuses', 'the action is reported'],
    actions: [{ kind, summary, input }],
  });
  const n = await waitForDecision(run.run_id);
  return { run, n };
}

function runCommand(commandLine) {
  return new Promise(resolve => {
    // One string, handed to the shell as is: no re-joining or re-quoting between the seal and the execution.
    const child = spawn(commandLine, { stdio: ['inherit', 'pipe', 'pipe'], shell: true });
    let tail = '';
    const keep = chunk => { tail = (tail + chunk.toString()).slice(-2000); };
    child.stdout.on('data', c => { process.stdout.write(c); keep(c); });
    child.stderr.on('data', c => { process.stderr.write(c); keep(c); });
    child.on('close', code => resolve({ code: code ?? 1, tail }));
    child.on('error', e => resolve({ code: 127, tail: String(e.message) }));
  });
}

// --- Commands -----------------------------------------------------------------------------------------------------
const [cmd, ...args] = process.argv.slice(2);
try {
  switch (cmd) {
    case 'hash': print({ input_hash: await inputHash(readJsonFile(args[0] ?? die('hash <input.json>'))) }); break;
    case 'policy': print(await api('GET', '/api/policy')); break;
    case 'ledger': print(await api('GET', '/api/ledger/verify')); break;
    case 'open': print(await api('POST', '/api/runs', readJsonFile(args[0] ?? die('open <run.json>')))); break;
    case 'next': print(await api('POST', `/api/runs/${args[0] ?? die('next <run_id>')}/next`, {})); break;
    case 'status': print(await api('GET', `/api/runs/${args[0] ?? die('status <run_id>')}`)); break;
    case 'report': {
      const [runId, index, outcome, evidenceFile, receipt] = args;
      if (!runId || index === undefined || !outcome) die('report <run_id> <index> done|failed [evidence.json] [receipt]');
      print(await api('POST', `/api/runs/${runId}/report`, { index: Number(index), outcome, evidence: evidenceFile ? readJsonFile(evidenceFile) : {}, receipt }));
      break;
    }
    case 'verify': {
      const [kind, token, file] = args;
      if (!kind || !token || !file) die('verify <kind> <receipt> <input.json>');
      const r = await verifyReceipt(kind, token, readJsonFile(file));
      if (!r.ok) die(`Receipt refused: ${r.why}`, 1);
      print({ ok: true, receipt_id: r.payload.receipt_id, kind: r.payload.kind, sealed_at: r.payload.sealed_at });
      break;
    }
    case 'gate': {
      const [kind, summary, file] = args;
      if (!kind || !summary || !file) die('gate <kind> "<summary>" <input.json>');
      const { run, n } = await gate(kind, summary, readJsonFile(file));
      print({ run_id: run.run_id, ...n });
      process.exit(n.decision === 'go' ? 0 : 1);
    }
    case 'run': {
      const [kind, summary, commandLine, ...extra] = args;
      if (!kind || !summary || !commandLine || extra.length) die('run <kind> "<summary>" "<command line>"  (the command line is ONE quoted argument)');
      const input = { command: commandLine, cwd: process.cwd() };
      const { run, n } = await gate(kind, summary, input);
      if (n.decision !== 'go') { print({ run_id: run.run_id, ...n }); process.exit(1); }
      if (n.receipt) {
        const r = await verifyReceipt(kind, n.receipt, input);
        if (!r.ok) die(`Receipt refused: ${r.why}`, 1);
      }
      console.error(`Sealed. Running: ${input.command}`);
      const result = await runCommand(commandLine);
      const outcome = result.code === 0 ? 'done' : 'failed';
      const evidence = { exit_code: result.code, output_tail: result.tail.slice(-1500) };
      print(await api('POST', `/api/runs/${run.run_id}/report`, { index: 0, outcome, evidence, receipt: n.receipt }));
      process.exit(result.code === 0 ? 0 : 1);
    }
    default:
      die('Commands: run, gate, verify, open, next, status, report, hash, policy, ledger. See the header of clients/seal.mjs.');
  }
} catch (e) {
  die(`${e.code ? e.code + ': ' : ''}${e.message}`, e.status === 409 ? 1 : 2);
}
