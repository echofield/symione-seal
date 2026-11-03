// End-to-end smoke against a running Seal (local `wrangler dev` or the deployed Worker), the way an agent and a phone
// would use it: open → go → report → wait → sign in → seal on the page → receipt → redeem → report → ledger intact.
// Also proves the refusals: acting before the seal, a second redeem, a wrong input, a forged form, a foreign origin.
//
//   node scripts/smoke.mjs <base-url> <secrets-file>
//   (secrets file = private/SEAL_LOCAL.txt or private/SEAL_SECRETS.txt: "Operator password: …" + "SEAL_AGENT_KEY=…")

import { readFileSync } from 'node:fs';

const [base, file] = process.argv.slice(2);
if (!base || !file) { console.log('Usage: node scripts/smoke.mjs <base-url> <secrets-file>'); process.exit(2); }
const text = readFileSync(file, 'utf8');
const password = text.match(/Operator password[^:]*:\s*(\S+)/)?.[1];
const key = text.match(/SEAL_AGENT_KEY=(\S+)/)?.[1];
if (!password || !key) { console.log('Secrets file lacks the password or agent key.'); process.exit(2); }

let failures = 0;
const check = (ok, label, extra = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${extra ? '  ' + extra : ''}`); if (!ok) failures++; };
const api = async (method, path, body) => {
  const res = await fetch(base + path, { method, headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, data: await res.json().catch(() => null) };
};

const agent = `smoke@${new Date().toISOString().slice(0, 19)}`;
const opened = await api('POST', '/api/runs', {
  agent, intent: 'Smoke test of the Seal: draft, then a sealed message.', plan: ['Draft', 'Send once sealed'],
  stop_conditions: ['the message is reported'],
  actions: [
    { kind: 'draft', summary: 'Draft a test note', input: { text: 'hello' } },
    { kind: 'send_message', summary: 'Send the smoke-test message to the house inbox', input: { to: 'house', text: 'smoke test' } },
  ],
});
check(opened.status === 201, 'open run', `${opened.status} ${opened.data?.run_id ?? JSON.stringify(opened.data)}`);
const runId = opened.data.run_id;
check((await api('POST', `/api/runs/${runId}/next`, {})).data?.decision === 'go', 'draft → go');
check((await api('POST', `/api/runs/${runId}/report`, { index: 0, outcome: 'done' })).data?.cursor === 1, 'report draft');
const wait = (await api('POST', `/api/runs/${runId}/next`, {})).data;
check(wait?.decision === 'wait' && wait.seal_url?.startsWith(base), 'sealed kind → wait', wait?.seal_url);
check((await api('POST', `/api/runs/${runId}/report`, { index: 1, outcome: 'done', evidence: { id: 'x' } })).status === 409, 'acting before the seal is refused');

// The phone.
const login = await fetch(base + '/login', { method: 'POST', redirect: 'manual', headers: { origin: base, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ password, next: '/' }) });
const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
check(login.status === 303 && cookie.startsWith('seal_session='), 'operator sign-in');
const sealPath = new URL(wait.seal_url).pathname;
const html = await (await fetch(base + sealPath, { headers: { cookie } })).text();
const token = html.match(/name="t" value="([^"]+)"/)?.[1];
check(!!token && html.includes('Send the smoke-test message'), 'seal page shows the exact action');
const post = (headers, t, decision = 'seal') => fetch(base + sealPath, { method: 'POST', redirect: 'manual', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams({ t, decision, note: 'smoke' }) });
check((await post({ origin: 'https://evil.example' }, token)).status === 403, 'foreign origin refused');
check((await post({ origin: base }, 'forged')).status === 403, 'forged form token refused');
check((await post({ origin: base }, token)).status === 303, 'SEAL pressed');
check((await post({ origin: base }, token, 'refuse')).status === 409, 'second decision refused');

const go = (await api('POST', `/api/runs/${runId}/next`, {})).data;
check(go?.decision === 'go' && typeof go.receipt === 'string', 'after the seal → go with a receipt');
check((await api('POST', '/api/receipts/redeem', { receipt: go.receipt, input_hash: 'sha256:' + '0'.repeat(64), kind: 'send_message' })).data?.error?.code === 'RECEIPT_MISMATCH', 'receipt refuses another input');
check((await api('POST', '/api/receipts/redeem', { receipt: go.receipt, input_hash: go.input_hash, kind: 'deploy_production' })).data?.error?.code === 'RECEIPT_MISMATCH', 'receipt refuses another kind');
check((await api('POST', '/api/receipts/redeem', { receipt: go.receipt, input_hash: go.input_hash, kind: 'send_message' })).data?.ok === true, 'receipt redeemed once');
check((await api('POST', '/api/receipts/redeem', { receipt: go.receipt, input_hash: go.input_hash, kind: 'send_message' })).data?.error?.code === 'RECEIPT_USED', 'second redeem refused');
const done = (await api('POST', `/api/runs/${runId}/report`, { index: 1, outcome: 'done', evidence: { delivered_to: 'house', at: new Date().toISOString() }, receipt: go.receipt })).data;
check(done?.status === 'completed', 'report with evidence completes the run');
const ledger = (await api('GET', '/api/ledger/verify')).data;
check(ledger?.intact === true, 'ledger verifies', `${ledger?.count} events, head ${ledger?.head?.hash?.slice(0, 20)}…`);
const status = (await api('GET', `/api/runs/${runId}`)).data;
console.log('events:', status.events.map(e => e.action).join(' → '));
console.log(failures ? `\n${failures} FAILED` : '\nALL PASS');
process.exit(failures ? 1 : 0);
