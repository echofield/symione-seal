// Secrets never land in the ledger or on a page. Revived from OP-CHORE (Opera_final/lib/kernel/redact.ts), with the
// JWT rule narrowed: the old pattern redacted any "a.b.c" (domains, file names, versions).

const PATTERNS: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED:private-key]'],
  [/\bsk-ant-[A-Za-z0-9_-]{20,}/g, '[REDACTED:anthropic-key]'],
  [/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g, '[REDACTED:openai-key]'],
  [/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g, '[REDACTED:stripe-key]'],
  [/\bwhsec_[A-Za-z0-9]{16,}/g, '[REDACTED:webhook-secret]'],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g, '[REDACTED:github-token]'],
  [/\bgithub_pat_[A-Za-z0-9_]{40,}/g, '[REDACTED:github-token]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED:aws-key]'],
  [/\bAIza[0-9A-Za-z_-]{30,}/g, '[REDACTED:google-key]'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, '[REDACTED:slack-token]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[REDACTED:jwt]'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/gi, 'Bearer [REDACTED]'],
  // key=value, key: value, and "key": "value" written inside a string.
  [/\b(password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key)("?\s*[:=]\s*)("?)[^\s"',;]{6,}\3/gi, '$1$2$3[REDACTED]$3'],
];

// Matched per word of the member name (camelCase and snake_case split): db_password, AWS_SECRET_ACCESS_KEY, apiKey,
// clientSecret, access_token — but not max_tokens or secretary_name.
const SECRET_WORDS = /(^|_)(password|passwd|passphrase|secret|token|apikey|api_key|private_key|privatekey|access_key|accesskey|credential|credentials|authorization|cookie|session_secret)($|_)/;
const isSecretName = (key: string) => SECRET_WORDS.test(key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[-.\s]/g, '_').toLowerCase());

export function redact(text: string): string {
  let out = text;
  for (const [re, replacement] of PATTERNS) out = out.replace(re, replacement);
  return out;
}

/** Redacts strings anywhere in a JSON value; a member whose name says it is a secret is replaced whole. */
export function redactValue(value: unknown, depth = 0): unknown {
  if (depth > 64) return '[REDACTED:too-deep]';
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map(v => redactValue(v, depth + 1));
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const isPrivateJwk = typeof obj.kty === 'string' && obj.d !== undefined;
    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(obj)) {
      const secret = (isSecretName(key) || (isPrivateJwk && ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'].includes(key))) && nested !== null && nested !== '';
      // defineProperty: a member named "__proto__" stays a member instead of vanishing.
      Object.defineProperty(out, key, { value: secret ? '[REDACTED]' : redactValue(nested, depth + 1), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return value;
}
