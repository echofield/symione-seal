// Seal receipts: an Ed25519-signed statement that a person sealed one exact action (bound by its input hash),
// valid for a short time and redeemable once. WebCrypto only, so the Worker, Node and clients/seal.mjs agree.

import { canonical } from './canonical';

export interface ReceiptPayload {
  v: 1;
  type: 'symione.seal.receipt';
  receipt_id: string;
  run_id: string;
  index: number;
  kind: string;
  input_hash: string;
  sealed_by: string;
  sealed_at: string;
  expires_at: string;
  issuer: string;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const fromB64url = (s: string) => {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('not base64url');
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
};

export async function importSigningKey(jwkJson: string): Promise<CryptoKey> {
  const { kty, crv, x, d } = JSON.parse(jwkJson) as JsonWebKey;
  if (kty !== 'OKP' || crv !== 'Ed25519' || !x || !d) throw new Error('SEAL_SIGNING_JWK must be a private Ed25519 JWK');
  // Only the key material: Node 25 exports alg "Ed25519" (RFC 9864), which workerd refuses ("EdDSA" or none).
  return crypto.subtle.importKey('jwk', { kty, crv, x, d }, { name: 'Ed25519' }, false, ['sign']);
}

/** The public half of the private JWK, safe to publish. */
export function publicJwk(jwkJson: string): JsonWebKey {
  const { kty, crv, x } = JSON.parse(jwkJson) as JsonWebKey;
  return { kty, crv, x };
}

export async function signReceipt(key: CryptoKey, payload: ReceiptPayload): Promise<string> {
  const body = enc.encode(canonical(payload));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, key, body));
  return `${b64url(body)}.${b64url(sig)}`;
}

export type ReceiptCheck =
  | { ok: true; payload: ReceiptPayload }
  | { ok: false; code: 'RECEIPT_INVALID' | 'RECEIPT_MISMATCH' | 'RECEIPT_EXPIRED'; message: string };

/** Signature, shape, expected input hash and expiry (skipped when nowIso is null). Single use is enforced by the
 *  Seal's database, not here. */
export async function checkReceipt(publicKey: JsonWebKey, token: string, expectedInputHash: string | null, nowIso: string | null): Promise<ReceiptCheck> {
  const invalid = (message: string): ReceiptCheck => ({ ok: false, code: 'RECEIPT_INVALID', message });
  if (typeof token !== 'string' || token.length > 4096) return invalid('Receipt is not a token.');
  const parts = token.split('.');
  if (parts.length !== 2) return invalid('Receipt is not a token.');
  let body: Uint8Array, sig: Uint8Array;
  try { body = fromB64url(parts[0]); sig = fromB64url(parts[1]); } catch { return invalid('Receipt is not base64url.'); }
  const key = await crypto.subtle.importKey('jwk', { kty: publicKey.kty, crv: publicKey.crv, x: publicKey.x }, { name: 'Ed25519' }, false, ['verify']);
  if (!(await crypto.subtle.verify({ name: 'Ed25519' }, key, sig as BufferSource, body as BufferSource))) return invalid('Signature does not verify.');
  let payload: ReceiptPayload;
  try { payload = JSON.parse(dec.decode(body)) as ReceiptPayload; } catch { return invalid('Receipt body is not JSON.'); }
  if (!payload || payload.v !== 1 || payload.type !== 'symione.seal.receipt' || typeof payload.receipt_id !== 'string'
    || typeof payload.input_hash !== 'string' || typeof payload.expires_at !== 'string') return invalid('Not a seal receipt.');
  try { if (canonical(payload) !== dec.decode(body)) return invalid('Receipt body is not canonical.'); } catch { return invalid('Receipt body is not canonical.'); }
  if (expectedInputHash !== null && payload.input_hash !== expectedInputHash) {
    return { ok: false, code: 'RECEIPT_MISMATCH', message: 'The receipt was sealed for a different action input.' };
  }
  if (nowIso !== null && !(nowIso < payload.expires_at)) return { ok: false, code: 'RECEIPT_EXPIRED', message: 'The receipt has expired.' };
  return { ok: true, payload };
}
