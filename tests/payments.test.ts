// The payments path: a person seals one PaymentIntent's exact parameters, and the downstream refuses everything else.
// Runs the real Worker (tests/harness.ts) with a mock Stripe that records what reaches it.

import { describe, expect, it } from 'vitest';
import { digest, jsonSafe } from '../src/core/canonical';
import { moneyLine } from '../src/worker/pages';
import { inputHash } from '../clients/verify.mjs';
import { chargeWithReceipt, formEncode } from '../examples/stripe-charge.mjs';
import { AGENT_KEY, ORIGIN, makeHarness } from './harness';

const params = {
  amount: 4200, currency: 'eur', description: 'Annual API plan, ordered by the procurement agent',
  payment_method: 'pm_card_visa', payment_method_types: ['card'], confirm: true,
};

describe('clients/verify.mjs hashes the same bytes as the Worker', () => {
  it('for every shape an input can take', async () => {
    const inputs: unknown[] = [
      params,
      { nested: { b: [1, 2, { c: null }], a: 'é', z: true }, skip: undefined },
      { price: 12.5, big: 2 ** 60, neg: -0, list: [] },
      'a bare string', 0, [],
    ];
    for (const input of inputs) expect(await inputHash(input)).toBe(await digest(jsonSafe(input)));
  });
});

describe('the amount on the phone comes from the sealed input', () => {
  it('formats minor units the way Stripe counts them', () => {
    expect(moneyLine('charge_payment', params)).toBe('42.00 EUR');
    expect(moneyLine('charge_payment', { amount: 5, currency: 'usd' })).toBe('0.05 USD');
    expect(moneyLine('charge_payment', { amount: 123456789, currency: 'usd' })).toBe('1,234,567.89 USD');
    expect(moneyLine('charge_payment', { amount: 500, currency: 'JPY' })).toBe('500 JPY');
    expect(moneyLine('charge_payment', { amount: 1500, currency: 'kwd' })).toBe('1.500 KWD');
    // An agent whose summary says "EUR 4.20" over an input of 420000: the person reads the input's figure.
    expect(moneyLine('charge_payment', { amount: 420000, currency: 'eur', description: 'EUR 4.20' })).toBe('4,200.00 EUR');
  });
  it('says nothing when there is no amount it can trust', () => {
    expect(moneyLine('send_email', params)).toBeNull();
    expect(moneyLine('charge_payment', { amount: 42.5, currency: 'eur' })).toBeNull();
    expect(moneyLine('charge_payment', { amount: '4200', currency: 'eur' })).toBeNull();
    expect(moneyLine('charge_payment', { amount: 4200, currency: 'euro' })).toBeNull();
  });
});

async function sealedCharge() {
  const h = await makeHarness();
  const opened = await h.agent('/api/runs', {
    agent: 'procurement-agent@acme', intent: 'Renew the annual API plan before it lapses.',
    plan: ['Charge the card on file once a person seals it'], stop_conditions: ['the person refuses'],
    actions: [{ kind: 'charge_payment', summary: 'Charge EUR 42.00 for the annual API plan', input: params }],
  });
  const wait = (await h.agent(`/api/runs/${opened.data.run_id}/next`, {})).data;
  await h.login();
  const html = await (await h.page(`/seal/${wait.approval_id}`)).text();
  expect((await h.decide(wait.approval_id, 'seal')).status).toBe(303);
  const go = (await h.agent(`/api/runs/${opened.data.run_id}/next`, {})).data;
  expect(go.decision).toBe('go');

  const stripeCalls: { url: string; headers: Headers; body: string }[] = [];
  const stripeFetch = async (url: string, init: RequestInit) => {
    stripeCalls.push({ url, headers: new Headers(init.headers), body: String(init.body) });
    return new Response(JSON.stringify({ id: 'pi_test_1', object: 'payment_intent', status: 'succeeded', amount: 4200, currency: 'eur' }), { status: 200 });
  };
  const seal = { url: ORIGIN, agentKey: AGENT_KEY, now: h.now, fetch: (url: string, init?: RequestInit) => h.app.fetch(new Request(url, init)) };
  return { h, runId: opened.data.run_id, html, receipt: go.receipt as string, stripeCalls, stripeFetch, seal };
}

describe('examples/stripe-charge.mjs: no PaymentIntent without the seal on these exact parameters', () => {
  it('shows the person the amount, then charges once, with the receipt as the idempotency key', async () => {
    const { h, runId, html, receipt, stripeCalls, stripeFetch, seal } = await sealedCharge();
    expect(html).toContain('Amount, read from the sealed input');
    expect(html).toContain('42.00 EUR');

    // An agent that changes one cent after the seal is refused before Stripe hears of it.
    await expect(chargeWithReceipt({ params: { ...params, amount: 4201 }, receipt, seal, stripe: { key: 'sk_test_x', fetch: stripeFetch } }))
      .rejects.toMatchObject({ code: 'RECEIPT_MISMATCH' });
    // A live key is refused by the example.
    await expect(chargeWithReceipt({ params, receipt, seal, stripe: { key: 'sk_live_x', fetch: stripeFetch } }))
      .rejects.toMatchObject({ code: 'LIVE_KEY_REFUSED' });
    expect(stripeCalls).toHaveLength(0);

    const r = await chargeWithReceipt({ params, receipt, seal, stripe: { key: 'sk_test_x', fetch: stripeFetch } });
    expect(r.sent).toBe(true);
    expect(stripeCalls).toHaveLength(1);
    const [call] = stripeCalls;
    const receiptId = JSON.parse(Buffer.from(receipt.split('.')[0], 'base64url').toString()).receipt_id;
    expect(call.url).toBe('https://api.stripe.com/v1/payment_intents');
    expect(call.headers.get('idempotency-key')).toBe(receiptId);
    const sent = new URLSearchParams(call.body);
    expect(sent.get('amount')).toBe('4200');
    expect(sent.get('currency')).toBe('eur');
    expect(sent.get('payment_method_types[0]')).toBe('card');
    expect(sent.get('confirm')).toBe('true');
    expect(sent.get('metadata[seal_receipt_id]')).toBe(receiptId);
    expect(sent.get('metadata[seal_input_hash]')).toBe(await inputHash(params));
    expect(sent.get('metadata[seal_run_id]')).toBe(runId);

    // The same receipt a second time: the Seal says it is used, Stripe is not called again.
    await expect(chargeWithReceipt({ params, receipt, seal, stripe: { key: 'sk_test_x', fetch: stripeFetch } }))
      .rejects.toMatchObject({ code: 'RECEIPT_USED' });
    expect(stripeCalls).toHaveLength(1);

    // The agent reports the PaymentIntent as its evidence; the run completes and the ledger holds.
    const done = await h.agent(`/api/runs/${runId}/report`, { index: 0, outcome: 'done', evidence: { payment_intent: 'pi_test_1' }, receipt });
    expect(done.data).toMatchObject({ status: 'completed' });
    expect((await h.agent('/api/ledger/verify')).data).toMatchObject({ intact: true });
  });

  it('refuses a receipt older than 15 minutes, and prints the request on a dry run', async () => {
    const a = await sealedCharge();
    a.h.advance(15 * 60 * 1000 + 1);
    await expect(chargeWithReceipt({ params, receipt: a.receipt, seal: a.seal, stripe: { key: 'sk_test_x', fetch: a.stripeFetch } }))
      .rejects.toMatchObject({ code: 'RECEIPT_EXPIRED' });
    expect(a.stripeCalls).toHaveLength(0);

    const b = await sealedCharge();
    const dry = await chargeWithReceipt({ params, receipt: b.receipt, seal: b.seal });
    expect(dry.sent).toBe(false);
    expect(dry.request.idempotencyKey).toMatch(/^rcpt_/);
    const body = new URLSearchParams(dry.request.body);
    for (const [k, v] of formEncode(params)) expect(body.get(k)).toBe(v);
    expect(b.stripeCalls).toHaveLength(0);
  });
});
