// Canonical JSON (RFC 8785 over strict JSON whose numbers are safe integers) and SHA-256.
// Ported from tonehold-service/foundation-sign.mjs `canonical()` (IFAH Foundation spec 0.01): nothing is left out,
// coerced or rounded. WebCrypto only, so a Worker, Node and a browser produce the same bytes.

const enc = new TextEncoder();
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

export function canonical(value: unknown, depth = 0): string {
  if (depth > 64) throw new Error('JSON nesting exceeds 64');
  if (value === null || typeof value === 'boolean') return String(value);
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new Error('invalid Unicode');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error('only safe integers (not negative zero)');
    return String(value);
  }
  if (Array.isArray(value)) {
    const out: string[] = [];
    for (let i = 0; i < value.length; i++) {
      if (!Object.hasOwn(value, i)) throw new Error('sparse array');
      out.push(canonical(value[i], depth + 1));
    }
    return '[' + out.join(',') + ']';
  }
  if (typeof value !== 'object') throw new Error('not a JSON value');
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new Error('not a plain JSON object');
  const obj = value as Record<string, unknown>;
  // Undefined members are absent members (JSON semantics), never "undefined".
  return '{' + Object.keys(obj).filter(k => obj[k] !== undefined).sort().map(k => {
    if (!k.isWellFormed()) throw new Error('invalid Unicode');
    return JSON.stringify(k) + ':' + canonical(obj[k], depth + 1);
  }).join(',') + '}';
}

/** Make a value canonicalisable: non-integer numbers become decimal strings, undefined is dropped. */
export function jsonSafe(value: unknown): unknown {
  if (value === undefined) return null;
  if (typeof value === 'number') return Number.isSafeInteger(value) && !Object.is(value, -0) ? value : String(value);
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    // defineProperty: a member named "__proto__" stays a member instead of vanishing from the hash.
    for (const [k, v] of Object.entries(value)) if (v !== undefined) Object.defineProperty(out, k, { value: jsonSafe(v), enumerable: true, writable: true, configurable: true });
    return out;
  }
  return value;
}

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? enc.encode(data) : data;
  return hex(await crypto.subtle.digest('SHA-256', bytes));
}

export const digest = async (value: unknown) => 'sha256:' + await sha256Hex(canonical(value));
