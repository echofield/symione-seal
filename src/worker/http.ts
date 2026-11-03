// Small HTTP helpers: JSON responses, typed errors, bounded body parsing, security headers.

export class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) { super(message); }
}

export const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'cache-control': 'no-store',
};

export function withSecurity(res: Response): Response {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) if (!out.headers.has(k)) out.headers.set(k, v);
  return out;
}

export const json = (data: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers } });

export function errorResponse(e: unknown): Response {
  if (e instanceof HttpError) return json({ error: { code: e.code, message: e.message } }, e.status);
  console.error('unhandled', e instanceof Error ? e.stack ?? e.message : String(e));
  return json({ error: { code: 'INTERNAL', message: 'Something went wrong on the Seal.' } }, 500);
}

export async function readText(request: Request, maxBytes: number): Promise<string> {
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (declared > maxBytes) throw new HttpError(413, 'TOO_LARGE', `Body exceeds ${maxBytes} bytes.`);
  const buf = new Uint8Array(await request.arrayBuffer());
  if (buf.byteLength > maxBytes) throw new HttpError(413, 'TOO_LARGE', `Body exceeds ${maxBytes} bytes.`);
  return new TextDecoder().decode(buf);
}

export async function readJson(request: Request, maxBytes = 256 * 1024): Promise<unknown> {
  const text = await readText(request, maxBytes);
  try { return JSON.parse(text); } catch { throw new HttpError(400, 'BAD_JSON', 'Body is not valid JSON.'); }
}

export async function readForm(request: Request, maxBytes = 16 * 1024): Promise<URLSearchParams> {
  return new URLSearchParams(await readText(request, maxBytes));
}
