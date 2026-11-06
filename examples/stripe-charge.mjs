#!/usr/bin/env node
// Downstream enforcement for payments: no PaymentIntent unless a person sealed these exact parameters.
//
//   node clients/seal.mjs gate charge_payment "Charge EUR 42.00 for the annual plan" examples/charge.json \
//     | node examples/stripe-charge.mjs examples/charge.json
//
// 1. Offline: the receipt's Ed25519 signature against the Seal's published key, its issuer, its kind, the SHA-256 of
//    these exact parameters, its expiry (clients/verify.mjs).
// 2. Online: the receipt is redeemed once at the Seal. A second use answers RECEIPT_USED.
// 3. Stripe: POST /v1/payment_intents with the sealed parameters as they are. The receipt id is the Idempotency-Key,
//    so a replay that reached Stripe would get the same PaymentIntent back. Metadata ties the charge to the seal.
//
// Without STRIPE_SECRET_KEY it prints the request it would send. A live key is refused: this is an example.
// Env: SEAL_URL, SEAL_AGENT_KEY, STRIPE_SECRET_KEY (sk_test_… only).

import { readFileSync } from 'node:fs';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { checkReceipt } from '../clients/verify.mjs';

const KIND = 'charge_payment';

/** Stripe's form encoding: nested objects as a[b], arrays as a[0]. */
export function formEncode(value, prefix = '', out = new URLSearchParams()) {
  if (value === null || value === undefined) return out;
  if (Array.isArray(value)) value.forEach((v, i) => formEncode(v, `${prefix}[${i}]`, out));
  else if (typeof value === 'object') for (const [k, v] of Object.entries(value)) formEncode(v, prefix ? `${prefix}[${k}]` : k, out);
  else out.append(prefix, String(value));
  return out;
}

/**
 * Verifies and redeems the receipt, then creates the PaymentIntent from the sealed parameters.
 * Throws an Error with a `code` (RECEIPT_INVALID | RECEIPT_MISMATCH | RECEIPT_EXPIRED | RECEIPT_USED | LIVE_KEY_REFUSED)
 * before any request reaches Stripe when a check fails.
 */
export async function chargeWithReceipt({ params, receipt, seal, stripe = {} }) {
  const refuse = (code, why) => Object.assign(new Error(`${code}: ${why}`), { code });
  const sealFetch = seal.fetch ?? fetch;
  if (stripe.key && !stripe.key.startsWith('sk_test_')) throw refuse('LIVE_KEY_REFUSED', 'this example only runs with a test-mode key');

  const wk = await (await sealFetch(`${seal.url}/.well-known/symione-seal.json`)).json();
  const check = await checkReceipt({ token: receipt, publicJwk: wk.public_key_jwk, issuer: wk.issuer, kind: KIND, input: params, now: seal.now?.() });
  if (!check.ok) throw refuse(check.code, check.why);

  const redeemed = await sealFetch(`${seal.url}/api/receipts/redeem`, {
    method: 'POST', headers: { authorization: `Bearer ${seal.agentKey}`, 'content-type': 'application/json' },
    body: JSON.stringify({ receipt, input_hash: check.input_hash, kind: KIND }),
  });
  if (!redeemed.ok) {
    const e = (await redeemed.json().catch(() => null))?.error;
    throw refuse(e?.code ?? 'RECEIPT_INVALID', e?.message ?? `redeem answered ${redeemed.status}`);
  }

  const { receipt_id, run_id, input_hash, sealed_at } = check.payload;
  const body = formEncode({ ...params, metadata: { ...params.metadata, seal_receipt_id: receipt_id, seal_run_id: run_id, seal_input_hash: input_hash, seal_sealed_at: sealed_at } });
  const request = { method: 'POST', url: `${stripe.apiBase ?? 'https://api.stripe.com'}/v1/payment_intents`, idempotencyKey: receipt_id, body: body.toString() };
  if (!stripe.key) return { sent: false, request };

  const res = await (stripe.fetch ?? fetch)(request.url, {
    method: 'POST', body,
    headers: { authorization: `Bearer ${stripe.key}`, 'idempotency-key': receipt_id, 'content-type': 'application/x-www-form-urlencoded' },
  });
  const paymentIntent = await res.json();
  if (!res.ok) throw Object.assign(new Error(`Stripe ${res.status}: ${paymentIntent?.error?.message ?? 'error'}`), { code: 'STRIPE_ERROR' });
  return { sent: true, request, paymentIntent };
}

// --- CLI: params file as argument, the gate's JSON (or a bare receipt) on stdin or as the second argument ----------
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const [paramsFile, receiptArg] = process.argv.slice(2);
  if (!paramsFile) { console.error('Usage: node examples/stripe-charge.mjs <params.json> [receipt]   (or pipe `seal.mjs gate` into it)'); process.exit(2); }
  const params = JSON.parse(readFileSync(paramsFile, 'utf8'));
  const raw = (receiptArg ?? readFileSync(0, 'utf8')).trim();
  const receipt = raw.startsWith('{') ? JSON.parse(raw).receipt : raw;
  if (!receipt) { console.error('No receipt: the seal was not granted.'); process.exit(1); }
  const url = (process.env.SEAL_URL ?? '').replace(/\/+$/, '');
  try {
    const r = await chargeWithReceipt({ params, receipt, seal: { url, agentKey: process.env.SEAL_AGENT_KEY }, stripe: { key: process.env.STRIPE_SECRET_KEY } });
    if (!r.sent) console.log(`Receipt verified and redeemed. Dry run (no STRIPE_SECRET_KEY), the request:\n\n${r.request.method} ${r.request.url}\nIdempotency-Key: ${r.request.idempotencyKey}\n\n${decodeURIComponent(r.request.body).split('&').join('\n')}`);
    else console.log(JSON.stringify({ payment_intent: r.paymentIntent.id, status: r.paymentIntent.status, amount: r.paymentIntent.amount, currency: r.paymentIntent.currency, metadata: r.paymentIntent.metadata }, null, 2));
  } catch (e) {
    console.error(`Refused: ${e.message}`);
    process.exit(1);
  }
}
