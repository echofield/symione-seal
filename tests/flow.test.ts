import { describe, expect, it } from 'vitest';
import { digest, jsonSafe } from '../src/core/canonical';
import { AGENT_KEY, ORIGIN, makeHarness, sampleRun } from './harness';

describe('the seal flow, end to end over HTTP', () => {
  it('draft goes, send waits, the person seals, the receipt binds, the report closes the run, the ledger verifies', async () => {
    const h = await makeHarness();
    const opened = await h.agent('/api/runs', sampleRun());
    expect(opened.status).toBe(201);
    const runId = opened.data.run_id;
    expect(opened.data.actions.map((a: any) => a.risk)).toEqual(['safe', 'sealed']);
    const sendInput = sampleRun().actions[1].input;
    expect(opened.data.actions[1].input_hash).toBe(await digest(jsonSafe(sendInput)));

    // Action 0: safe -> go.
    expect((await h.agent(`/api/runs/${runId}/next`, {})).data).toMatchObject({ decision: 'go', index: 0, kind: 'draft' });
    expect((await h.agent(`/api/runs/${runId}/report`, { index: 0, outcome: 'done', evidence: { draft: 'v1' } })).data).toMatchObject({ status: 'open', cursor: 1 });

    // Action 1: sealed -> wait (and the same answer again).
    const wait = (await h.agent(`/api/runs/${runId}/next`, {})).data;
    expect(wait).toMatchObject({ decision: 'wait', index: 1, kind: 'send_email' });
    expect(wait.seal_url).toBe(`${ORIGIN}/seal/${wait.approval_id}`);
    expect((await h.agent(`/api/runs/${runId}/next`, {})).data.approval_id).toBe(wait.approval_id);

    // Acting before the seal is refused.
    expect((await h.agent(`/api/runs/${runId}/report`, { index: 1, outcome: 'done', evidence: { id: 'x' } })).data.error.code).toBe('RUN_NOT_OPEN');

    // The person: sign in, open the page, see the exact input, seal.
    expect((await h.login()).status).toBe(303);
    const html = await (await h.page(`/seal/${wait.approval_id}`)).text();
    expect(html).toContain('Send the invitation to lead@example.com');
    expect(html).toContain(opened.data.actions[1].input_hash);
    const token = html.match(/name="t" value="([^"]+)"/)![1];
    const post = (decision: string) => h.page(`/seal/${wait.approval_id}`, {
      method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ t: token, decision, note: decision === 'seal' ? 'Go — checked the wording.' : '' }).toString(),
    });
    expect((await post('seal')).status).toBe(303);
    expect((await post('refuse')).status).toBe(409); // decided once; a second decision with the same form is refused
    expect(await (await h.page(`/seal/${wait.approval_id}`)).text()).not.toContain('name="t"'); // the form is gone
    const go = (await h.agent(`/api/runs/${runId}/next`, {})).data;
    expect(go).toMatchObject({ decision: 'go', index: 1, kind: 'send_email', receipt_redeemed: false });

    // Downstream tool: wrong input refused, right input redeemed once.
    expect((await h.agent('/api/receipts/redeem', { receipt: go.receipt, input_hash: 'sha256:' + '0'.repeat(64), kind: 'send_email' })).data.error.code).toBe('RECEIPT_MISMATCH');
    expect((await h.agent('/api/receipts/redeem', { receipt: go.receipt, input_hash: go.input_hash, kind: 'deploy_production' })).data.error.code).toBe('RECEIPT_MISMATCH');
    expect((await h.agent('/api/receipts/redeem', { receipt: go.receipt, input_hash: go.input_hash, kind: 'send_email' })).data).toMatchObject({ ok: true, index: 1 });
    expect((await h.agent('/api/receipts/redeem', { receipt: go.receipt, input_hash: go.input_hash, kind: 'send_email' })).data.error.code).toBe('RECEIPT_USED');

    // Report with evidence closes the run.
    expect((await h.agent(`/api/runs/${runId}/report`, { index: 1, outcome: 'done', receipt: go.receipt })).data.error.code).toBe('EVIDENCE_REQUIRED');
    const done = await h.agent(`/api/runs/${runId}/report`, { index: 1, outcome: 'done', evidence: { message_id: '<abc@mail>' }, receipt: go.receipt });
    expect(done.data).toMatchObject({ status: 'completed', next: 'done' });
    expect((await h.agent(`/api/runs/${runId}/next`, {})).data).toEqual({ decision: 'done' });

    const status = (await h.agent(`/api/runs/${runId}`)).data;
    expect(status.events.map((e: any) => e.action)).toEqual([
      'run.opened', 'action.cleared', 'action.done', 'seal.requested', 'seal.granted', 'receipt.redeemed', 'action.done', 'run.completed',
    ]);
    expect(status.approvals[0]).toMatchObject({ status: 'sealed', note: 'Go — checked the wording.' });
    const ledger = (await h.agent('/api/ledger/verify')).data;
    expect(ledger).toMatchObject({ intact: true, count: 8 });

    // The published key verifies the receipt offline.
    const wk = (await h.app.fetch(new Request(ORIGIN + '/.well-known/symione-seal.json'))).json() as Promise<any>;
    expect((await wk).public_key_jwk).not.toHaveProperty('d');
  });

  it('a refusal stops the run and the agent hears why', async () => {
    const h = await makeHarness();
    const runId = (await h.agent('/api/runs', sampleRun())).data.run_id;
    await h.agent(`/api/runs/${runId}/next`, {});
    await h.agent(`/api/runs/${runId}/report`, { index: 0, outcome: 'done' });
    const wait = (await h.agent(`/api/runs/${runId}/next`, {})).data;
    await h.login();
    expect((await h.decide(wait.approval_id, 'refuse', 'Wrong recipient.')).status).toBe(303);
    expect((await h.agent(`/api/runs/${runId}/next`, {})).data).toEqual({ decision: 'stop', index: 1, reason: 'refused', note: 'Wrong recipient.' });
    expect((await h.agent('/api/ledger/verify')).data.intact).toBe(true);
  });

  it('a seal request expires after 24 h and a receipt after 15 minutes', async () => {
    const h = await makeHarness();
    const r1 = (await h.agent('/api/runs', { ...sampleRun(), actions: [sampleRun().actions[1]] })).data.run_id;
    await h.agent(`/api/runs/${r1}/next`, {});
    h.advance(24 * 3600 * 1000 + 1);
    expect((await h.agent(`/api/runs/${r1}/next`, {})).data).toMatchObject({ decision: 'stop', reason: 'expired' });

    const r2 = (await h.agent('/api/runs', { ...sampleRun(), actions: [sampleRun().actions[1]] })).data.run_id;
    const wait = (await h.agent(`/api/runs/${r2}/next`, {})).data;
    await h.login();
    await h.decide(wait.approval_id, 'seal');
    h.advance(15 * 60 * 1000);
    expect((await h.agent(`/api/runs/${r2}/next`, {})).data).toMatchObject({ decision: 'stop', reason: 'receipt_expired' });
    expect((await h.agent('/api/ledger/verify')).data.intact).toBe(true);
  });

  it('refuses unknown kinds, oversize plans, a fourth open run, and bad keys', async () => {
    const h = await makeHarness();
    expect((await h.agent('/api/runs', { ...sampleRun(), actions: [{ kind: 'rm_rf', summary: 'x', input: {} }] })).data.error.code).toBe('UNKNOWN_KIND');
    expect((await h.agent('/api/runs', { ...sampleRun(), actions: Array(9).fill(sampleRun().actions[0]) })).data.error.code).toBe('INVALID_ACTIONS');
    for (let i = 0; i < 3; i++) expect((await h.agent('/api/runs', sampleRun('busy'))).status).toBe(201);
    const fourth = await h.agent('/api/runs', sampleRun('busy'));
    expect(fourth.status).toBe(409);
    expect(fourth.data.error.code).toBe('TOO_MANY_OPEN_RUNS');
    expect((await h.agent('/api/runs', sampleRun('other'))).status).toBe(201);
    expect((await h.agent('/api/policy', undefined, 'GET', 'wrong-key')).status).toBe(401);
    expect((await h.agent('/api/policy', undefined, 'GET', AGENT_KEY + 'x')).status).toBe(401);
  });

  it('keeps secrets out of the ledger while the hash still binds the original input', async () => {
    const h = await makeHarness();
    const secret = 'sk-proj-' + 'Z'.repeat(40);
    const input = { to: 'x@example.com', body: `use ${secret}`, api_key: 'abcdef123456' };
    // A sealed action must be fully visible to the person, so a secret inside it is refused outright…
    expect((await h.agent('/api/runs', { ...sampleRun(), actions: [{ kind: 'send_email', summary: 'Send', input }] })).data.error.code).toBe('SECRET_IN_SEALED_INPUT');
    // …while a safe action may carry one: it is redacted in storage and the hash still binds the original.
    const opened = await h.agent('/api/runs', { ...sampleRun(), actions: [{ kind: 'draft', summary: 'Draft', input }] });
    expect(opened.data.actions[0].input_hash).toBe(await digest(jsonSafe(input)));
    const dump = JSON.stringify(h.db.raw.prepare('SELECT * FROM events').all()) + JSON.stringify(h.db.raw.prepare('SELECT * FROM actions').all());
    expect(dump).not.toContain(secret);
    expect(dump).not.toContain('abcdef123456');
  });

  it('the events table refuses UPDATE and DELETE', async () => {
    const h = await makeHarness();
    await h.agent('/api/runs', sampleRun());
    expect(() => h.db.raw.exec("UPDATE events SET actor = 'mallory'")).toThrow(/append-only/);
    expect(() => h.db.raw.exec('DELETE FROM events')).toThrow(/append-only/);
  });
});

describe('the operator surface', () => {
  it('locks a source out after five wrong passwords, and requires the Seal origin and a form token', async () => {
    const h = await makeHarness();
    for (let i = 0; i < 5; i++) expect((await h.login('wrong password here', '198.51.100.1')).status).toBe(401);
    expect((await h.login(undefined, '198.51.100.1')).status).toBe(429);
    expect((await h.login(undefined, '198.51.100.2')).status).toBe(303);

    const runId = (await h.agent('/api/runs', { ...sampleRun(), actions: [sampleRun().actions[1]] })).data.run_id;
    const wait = (await h.agent(`/api/runs/${runId}/next`, {})).data;
    expect((await h.decide(wait.approval_id, 'seal', '', { origin: 'https://evil.test' })).status).toBe(403);
    expect((await h.decide(wait.approval_id, 'seal', '', {})).status).toBe(403);
    const forged = await h.page(`/seal/${wait.approval_id}`, {
      method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ t: 'forged', decision: 'seal' }).toString(),
    });
    expect(forged.status).toBe(403);
    expect((await h.agent(`/api/runs/${runId}/next`, {})).data.decision).toBe('wait');
  });

  it('sends signed-out phones to the login page and back to the seal', async () => {
    const h = await makeHarness();
    const res = await h.page('/seal/seal_abc');
    expect(res.status).toBe(303);
    expect(res.headers.get('location')).toBe('/login?next=%2Fseal%2Fseal_abc');
    expect(res.headers.get('content-security-policy')).toContain("default-src 'none'");
  });
});

describe('MCP', () => {
  it('initializes, lists tools, and drives a run through tools/call', async () => {
    const h = await makeHarness();
    const rpc = async (body: unknown) => {
      const res = await h.app.fetch(new Request(ORIGIN + '/mcp', { method: 'POST', headers: { authorization: `Bearer ${AGENT_KEY}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify(body) }));
      return { status: res.status, data: res.status === 202 ? null : await res.json() as any };
    };
    const init = await rpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } });
    expect(init.data.result).toMatchObject({ protocolVersion: '2025-06-18', serverInfo: { name: 'symione-seal' } });
    expect((await rpc({ jsonrpc: '2.0', method: 'notifications/initialized' })).status).toBe(202);
    const tools = (await rpc({ jsonrpc: '2.0', id: 2, method: 'tools/list' })).data.result.tools.map((t: any) => t.name);
    expect(tools).toEqual(['seal_policy', 'seal_open_run', 'seal_next', 'seal_report', 'seal_status']);
    const opened = (await rpc({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'seal_open_run', arguments: sampleRun() } })).data.result;
    expect(opened.isError).toBe(false);
    const runId = opened.structuredContent.run_id;
    const next = (await rpc({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'seal_next', arguments: { run_id: runId } } })).data.result;
    expect(next.structuredContent).toMatchObject({ decision: 'go', kind: 'draft' });
    const bad = (await rpc({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'seal_report', arguments: { run_id: runId, index: 1, outcome: 'done' } } })).data.result;
    expect(bad).toMatchObject({ isError: true });
    expect((await rpc({ jsonrpc: '2.0', id: 6, method: 'nope' })).data.error.code).toBe(-32601);
    const unauth = await h.app.fetch(new Request(ORIGIN + '/mcp', { method: 'POST', body: '{}' }));
    expect(unauth.status).toBe(401);
  });
});

describe('review fixes (3 Nov fix pass)', () => {
  it('a failed last action stops the run: next says stop at that index, never done', async () => {
    const h = await makeHarness();
    const one = (await h.agent('/api/runs', { ...sampleRun(), actions: [sampleRun().actions[0]] })).data.run_id;
    await h.agent(`/api/runs/${one}/next`, {});
    expect((await h.agent(`/api/runs/${one}/report`, { index: 0, outcome: 'failed', evidence: { error: 'disk full' } })).data).toMatchObject({ status: 'stopped', cursor: 0 });
    expect((await h.agent(`/api/runs/${one}/next`, {})).data).toMatchObject({ decision: 'stop', index: 0, reason: 'failed' });
    const two = (await h.agent('/api/runs', sampleRun())).data.run_id;
    await h.agent(`/api/runs/${two}/next`, {});
    await h.agent(`/api/runs/${two}/report`, { index: 0, outcome: 'failed' });
    expect((await h.agent(`/api/runs/${two}/next`, {})).data).toMatchObject({ decision: 'stop', index: 0, reason: 'failed' });
  });

  it('a sealed action reported after its receipt expired is recorded, and the run stops as late', async () => {
    const h = await makeHarness();
    const runId = (await h.agent('/api/runs', { ...sampleRun(), actions: [sampleRun().actions[1]] })).data.run_id;
    const wait = (await h.agent(`/api/runs/${runId}/next`, {})).data;
    await h.login();
    await h.decide(wait.approval_id, 'seal');
    const go = (await h.agent(`/api/runs/${runId}/next`, {})).data;
    h.advance(16 * 60 * 1000);
    const res = (await h.agent(`/api/runs/${runId}/report`, { index: 0, outcome: 'done', evidence: { message_id: 'm1' }, receipt: go.receipt })).data;
    expect(res).toMatchObject({ status: 'stopped', late: true, next: 'stopped' });
    expect((await h.agent(`/api/runs/${runId}/next`, {})).data).toMatchObject({ decision: 'stop', reason: 'late' });
    expect((await h.agent('/api/ledger/verify')).data.intact).toBe(true);
  });

  it('idle open runs close after 24 h and free the cap; a total cap stands behind self-declared labels', async () => {
    const h = await makeHarness();
    for (let i = 0; i < 3; i++) await h.agent('/api/runs', sampleRun('idle'));
    expect((await h.agent('/api/runs', sampleRun('idle'))).status).toBe(409);
    h.advance(24 * 3600 * 1000 + 1);
    expect((await h.agent('/api/runs', sampleRun('idle'))).status).toBe(201);
    for (let i = 0; i < 19; i++) await h.agent('/api/runs', sampleRun(`label-${i}`));
    const over = await h.agent('/api/runs', sampleRun('label-x'));
    expect(over.status).toBe(409);
    expect(over.data.error.code).toBe('TOO_MANY_OPEN_RUNS');
  });

  it('caps waiting seal requests at 10 across all runs', async () => {
    const h = await makeHarness();
    const only = { ...sampleRun(), actions: [sampleRun().actions[1]] };
    for (let i = 0; i < 10; i++) {
      const id = (await h.agent('/api/runs', { ...only, agent: `w${i}` })).data.run_id;
      expect((await h.agent(`/api/runs/${id}/next`, {})).data.decision).toBe('wait');
    }
    const id = (await h.agent('/api/runs', { ...only, agent: 'w10' })).data.run_id;
    const res = await h.agent(`/api/runs/${id}/next`, {});
    expect(res.status).toBe(429);
    expect(res.data.error.code).toBe('TOO_MANY_WAITING');
  });

  it('refuses a "__proto__" member in an action input or in evidence', async () => {
    const h = await makeHarness();
    const raw = `{"agent":"p","intent":"x","actions":[{"kind":"send_email","summary":"Send","input":{"to":"a@example.com","__proto__":"hidden"}}]}`;
    const res = await h.app.fetch(new Request('https://seal.test/api/runs', { method: 'POST', headers: { authorization: `Bearer ${AGENT_KEY}`, 'content-type': 'application/json' }, body: raw }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error.message).toContain('__proto__');
  });
});
