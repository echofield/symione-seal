// Password hashes for a deployed workspace: PBKDF2-SHA256 (WebCrypto, so the Worker and Node share one code path).
// Stored form: pbkdf2-sha256$<iterations>$<salt b64url>$<hash b64url>. Workers cap PBKDF2 at 100,000 iterations.

export const PBKDF2_ITERATIONS = 100_000;
const enc = new TextEncoder();

const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));

async function derive(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations }, key, 256));
}

export async function hashPassword(password: string, salt: Uint8Array = crypto.getRandomValues(new Uint8Array(16)), iterations = PBKDF2_ITERATIONS): Promise<string> {
  if (password.length < 12) throw new Error('A workspace password has at least 12 characters.');
  return `pbkdf2-sha256$${iterations}$${b64url(salt)}$${b64url(await derive(password, salt, iterations))}`;
}

/** Constant-time comparison of the derived key; false for a malformed stored hash. */
export async function verifyPassword(stored: string | undefined | null, password: string): Promise<boolean> {
  const parts = (stored ?? '').trim().split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2-sha256') return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 10_000 || iterations > PBKDF2_ITERATIONS) return false;
  let salt: Uint8Array, want: Uint8Array;
  try { salt = fromB64url(parts[2]); want = fromB64url(parts[3]); } catch { return false; }
  const got = await derive(password, salt, iterations);
  if (got.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got[i] ^ want[i];
  return diff === 0;
}
