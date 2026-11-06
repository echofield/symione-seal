// Verify a SYMIONE SEAL receipt. No dependencies: WebCrypto only, so it runs the same in Node 20+, Deno, Bun,
// a browser or a Worker. Copy this file into any system that must refuse to act without a person's seal.
//
//   import { checkReceipt, inputHash } from './verify.mjs';
//   const wk = await (await fetch(`${SEAL_URL}/.well-known/symione-seal.json`)).json();
//   const r = await checkReceipt({ token, publicJwk: wk.public_key_jwk, issuer: wk.issuer, kind: 'charge_payment', input });
//   if (!r.ok) throw new Error(r.why);
//   // then redeem it once: POST /api/receipts/redeem { receipt, input_hash, kind }
//
// The canonical form and the hash are byte-identical to the Worker's (src/core/canonical.ts); tests/verify.test.ts
// holds the two implementations to the same bytes.

const enc = new TextEncoder();
const dec = new TextDecoder();

/** RFC 8785 canonical JSON over strict JSON whose numbers are safe integers. */
export function canonical(value, depth = 0) {
  if (depth > 64) throw new Error('JSON nesting exceeds 64');
  if (value === null || typeof value === 'boolean') return String(value);
  if (typeof value === 'string') { if (!value.isWellFormed()) throw new Error('invalid Unicode'); return JSON.stringify(value); }
  if (typeof value === 'number') { if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error('only safe integers'); return String(value); }
  if (Array.isArray(value)) return '[' + value.map(v => canonical(v, depth + 1)).join(',') + ']';
  if (typeof value !== 'object') throw new Error('not a JSON value');
  return '{' + Object.keys(value).filter(k => value[k] !== undefined).sort()
    .map(k => JSON.stringify(k) + ':' + canonical(value[k], depth + 1)).join(',') + '}';
}

/** Non-integer numbers become decimal strings and undefined members are dropped, exactly as the Seal does. */
export function jsonSafe(value) {
  if (value === undefined) return null;
  if (typeof value === 'number') return Number.isSafeInteger(value) && !Object.is(value, -0) ? value : String(value);
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (v !== undefined) Object.defineProperty(out, k, { value: jsonSafe(v), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return value;
}

/** `sha256:` + hex SHA-256 of the canonical input. This is what a receipt binds. */
export async function inputHash(input) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(canonical(jsonSafe(input)))));
  return 'sha256:' + [...digest].map(b => b.toString(16).padStart(2, '0')).join('');
}

const fromB64url = s => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) throw new Error('not base64url');
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
};

/**
 * Offline check of a receipt for the action you are about to perform: Ed25519 signature against the Seal's published
 * key, canonical body, issuer, kind, input hash, expiry. Single use is enforced online by redeeming the receipt.
 * Returns { ok: true, payload, input_hash } or { ok: false, code, why }.
 */
export async function checkReceipt({ token, publicJwk, issuer, kind, input, now = new Date().toISOString() }) {
  const fail = (code, why) => ({ ok: false, code, why });
  if (typeof token !== 'string' || token.length > 4096) return fail('RECEIPT_INVALID', 'not a receipt token');
  const parts = token.split('.');
  if (parts.length !== 2) return fail('RECEIPT_INVALID', 'not a receipt token');
  let body, sig;
  try { body = fromB64url(parts[0]); sig = fromB64url(parts[1]); } catch { return fail('RECEIPT_INVALID', 'not base64url'); }
  const key = await crypto.subtle.importKey('jwk', { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x }, { name: 'Ed25519' }, false, ['verify']);
  if (!(await crypto.subtle.verify({ name: 'Ed25519' }, key, sig, body))) return fail('RECEIPT_INVALID', 'signature does not verify against the published key');
  let payload;
  try { payload = JSON.parse(dec.decode(body)); } catch { return fail('RECEIPT_INVALID', 'body is not JSON'); }
  if (!payload || payload.v !== 1 || payload.type !== 'symione.seal.receipt') return fail('RECEIPT_INVALID', 'not a seal receipt');
  if (canonical(payload) !== dec.decode(body)) return fail('RECEIPT_INVALID', 'body is not canonical');
  if (issuer !== undefined && payload.issuer !== issuer) return fail('RECEIPT_INVALID', `issued by ${payload.issuer}, expected ${issuer}`);
  if (payload.kind !== kind) return fail('RECEIPT_MISMATCH', `sealed for ${payload.kind}, not ${kind}`);
  const hash = await inputHash(input);
  if (payload.input_hash !== hash) return fail('RECEIPT_MISMATCH', 'sealed for a different input');
  if (!(now < payload.expires_at)) return fail('RECEIPT_EXPIRED', 'expired');
  return { ok: true, payload, input_hash: hash };
}
