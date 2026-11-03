// Operator session cookie and form tokens: HMAC-SHA256 with SESSION_SECRET. Stateless; 12-hour sessions.

import { b64url, fromB64url } from './receipt';

const enc = new TextEncoder();
export const SESSION_COOKIE = 'seal_session';
export const SESSION_SECONDS = 12 * 3600;

async function hmacKey(secret: string) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function hmac(secret: string, message: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(message))));
}

async function hmacVerify(secret: string, message: string, mac: string): Promise<boolean> {
  let sig: Uint8Array;
  try { sig = fromB64url(mac); } catch { return false; }
  return crypto.subtle.verify('HMAC', await hmacKey(secret), sig as BufferSource, enc.encode(message));
}

/** Token form: `<expiresEpochSeconds>.<nonce>.<mac>`. */
export async function issueSession(secret: string, nowEpoch: number): Promise<string> {
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(12)));
  const body = `${nowEpoch + SESSION_SECONDS}.${nonce}`;
  return `${body}.${await hmac(secret, `session.${body}`)}`;
}

export async function checkSession(secret: string, token: string | null, nowEpoch: number): Promise<string | null> {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [exp, nonce, mac] = parts;
  if (!/^\d{1,12}$/.test(exp) || Number(exp) <= nowEpoch) return null;
  if (!(await hmacVerify(secret, `session.${exp}.${nonce}`, mac))) return null;
  return nonce;
}

/** A form token ties a POST to this session and this approval. */
export const formToken = (secret: string, sessionNonce: string, approvalId: string) => hmac(secret, `form.${sessionNonce}.${approvalId}`);
export const checkFormToken = (secret: string, sessionNonce: string, approvalId: string, token: string) =>
  hmacVerify(secret, `form.${sessionNonce}.${approvalId}`, token);

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get('cookie') ?? '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

/** Constant-time equality through SHA-256 (lengths never leak). */
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([a, b].map(s => crypto.subtle.digest('SHA-256', enc.encode(s))));
  const ax = new Uint8Array(x), by = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < ax.length; i++) diff |= ax[i] ^ by[i];
  return diff === 0;
}
