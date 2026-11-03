// SYMIONE SEAL Worker: one fetch handler built from env + injected dependencies, so tests run it over node:sqlite
// with a fixed clock (pattern from MANDATE createApp).

import { LIMITS } from '../core/policy';
import { CHAIN_METHOD } from '../core/chain';
import { verifyPassword } from '../core/password';
import { importSigningKey, publicJwk } from '../core/receipt';
import { SESSION_COOKIE, SESSION_SECONDS, checkFormToken, checkSession, formToken, issueSession, readCookie, safeEqual } from '../core/session';
import { one, run, type Db } from './db';
import * as engine from './engine';
import { HttpError, errorResponse, json, readForm, readJson, withSecurity } from './http';
import { verifyLedger } from './ledger';
import { handleMcp } from './mcp';
import { inboxPage, loginPage, messagePage, runPage, sealPage } from './pages';

export interface Env {
  DB: Db;
  SEAL_ENV?: string;
  SEAL_AGENT_KEY?: string;
  SEAL_OPERATOR_HASH?: string;
  SESSION_SECRET?: string;
  SEAL_SIGNING_JWK?: string;
}
export interface Deps { now?: () => string }

const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES_PER_IP = 5;

export function createApp(env: Env, deps: Deps = {}) {
  const now = deps.now ?? (() => new Date().toISOString());
  const newId = (prefix: string) => {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return `${prefix}_${[...bytes].map(b => (b % 36).toString(36)).join('')}`;
  };
  let keyPromise: Promise<CryptoKey> | null = null;
  const need = (name: keyof Env): string => {
    const v = env[name];
    if (typeof v !== 'string' || !v) throw new HttpError(500, 'MISCONFIGURED', `${name} is not configured on this Seal.`);
    return v;
  };
  const signingJwk = () => need('SEAL_SIGNING_JWK');
  const signingKey = () => (keyPromise ??= importSigningKey(signingJwk()).catch(e => { keyPromise = null; throw e; }));
  const ctxFor = (url: URL): engine.Ctx => ({ db: env.DB, now, newId, origin: url.origin, signingKey, signingJwk });
  const epoch = () => Math.floor(Date.parse(now()) / 1000);

  async function requireAgent(request: Request) {
    const header = request.headers.get('authorization') ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
    const key = need('SEAL_AGENT_KEY');
    if (!token || !(await safeEqual(token, key))) throw new HttpError(401, 'UNAUTHENTICATED', 'A valid agent key is required.');
  }

  async function session(request: Request): Promise<string | null> {
    return checkSession(need('SESSION_SECRET'), readCookie(request, SESSION_COOKIE), epoch());
  }

  function sameOrigin(request: Request, url: URL) {
    if (request.headers.get('origin') !== url.origin) throw new HttpError(403, 'BAD_ORIGIN', 'This form must be sent from the Seal itself.');
  }

  const redirect = (to: string, headers: Record<string, string> = {}) => new Response(null, { status: 303, headers: { location: to, ...headers } });
  const safeNext = (v: string | null) => (v && /^\/(seal|runs)\/[A-Za-z0-9_]{1,64}$/.test(v) ? v : '/');
  const clientIp = (request: Request) => request.headers.get('cf-connecting-ip') ?? 'local';

  async function handleLogin(request: Request, url: URL): Promise<Response> {
    sameOrigin(request, url);
    const form = await readForm(request);
    const next = safeNext(form.get('next'));
    const since = new Date(Date.parse(now()) - LOGIN_WINDOW_MS).toISOString();
    const ip = clientIp(request);
    // Record the attempt as a failure FIRST, then count: concurrent attempts each see the others, so a burst cannot
    // slip past the limit (check-then-act). A success flips its own row afterwards. The limit is per source only: the
    // password is ~124 random bits, and a global limit would let anyone lock the operator out.
    const at = now();
    const attemptId = (await one<{ id: number }>(env.DB, 'INSERT INTO login_attempts (at, ok, ip) VALUES (?, 0, ?) RETURNING id', at, ip))?.id;
    const failures = await one<{ n: number }>(env.DB, 'SELECT COUNT(*) AS n FROM login_attempts WHERE ok = 0 AND ip = ? AND at > ?', ip, since);
    if ((failures?.n ?? 0) > LOGIN_MAX_FAILURES_PER_IP) {
      const res = loginPage(next, 'Too many attempts. Wait 15 minutes and try again.');
      return new Response(res.body, { status: 429, headers: res.headers });
    }
    const ok = await verifyPassword(need('SEAL_OPERATOR_HASH'), form.get('password') ?? '');
    if (ok && attemptId !== undefined) await run(env.DB, 'UPDATE login_attempts SET ok = 1 WHERE id = ?', attemptId);
    await run(env.DB, 'DELETE FROM login_attempts WHERE at < ?', new Date(Date.parse(now()) - 24 * 3600 * 1000).toISOString());
    if (!ok) {
      const res = loginPage(next, 'That password does not open this Seal.');
      return new Response(res.body, { status: 401, headers: res.headers });
    }
    const token = await issueSession(need('SESSION_SECRET'), epoch());
    return redirect(next, { 'set-cookie': `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}` });
  }

  async function route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const ctx = ctxFor(url);
    let m: RegExpMatchArray | null;

    if (path === '/health' && method === 'GET') return json({ ok: true, service: 'symione-seal', version: '0.1.0' });
    if (path === '/.well-known/symione-seal.json' && method === 'GET') {
      return json({
        issuer: url.origin, alg: 'Ed25519', public_key_jwk: publicJwk(signingJwk()), receipt_ttl_seconds: LIMITS.receiptTtlSeconds,
        receipt_format: 'base64url(canonical JSON payload) "." base64url(Ed25519 signature over those bytes)', ledger_method: CHAIN_METHOD,
      });
    }

    // ---- Agent surface -------------------------------------------------------------------------------------
    if (path === '/mcp') { await requireAgent(request); return handleMcp(request, ctx); }
    if (path.startsWith('/api/')) {
      await requireAgent(request);
      if (path === '/api/policy' && method === 'GET') return json(engine.policy());
      if (path === '/api/runs' && method === 'POST') return json(await engine.openRun(ctx, await readJson(request)), 201);
      if ((m = path.match(/^\/api\/runs\/([^/]+)\/next$/)) && method === 'POST') return json(await engine.next(ctx, m[1]));
      if ((m = path.match(/^\/api\/runs\/([^/]+)\/report$/)) && method === 'POST') return json(await engine.report(ctx, m[1], await readJson(request)));
      if ((m = path.match(/^\/api\/runs\/([^/]+)$/)) && method === 'GET') return json(await engine.status(ctx, m[1]));
      if (path === '/api/receipts/redeem' && method === 'POST') return json(await engine.redeem(ctx, await readJson(request)));
      if (path === '/api/ledger/verify' && method === 'GET') return json(await verifyLedger(env.DB));
      throw new HttpError(404, 'NOT_FOUND', 'No such route.');
    }

    // ---- Operator surface ----------------------------------------------------------------------------------
    if (path === '/login' && method === 'GET') return loginPage(safeNext(url.searchParams.get('next')));
    if (path === '/login' && method === 'POST') return handleLogin(request, url);
    if (path === '/logout' && method === 'POST') {
      sameOrigin(request, url);
      return redirect('/login', { 'set-cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` });
    }

    const isPage = path === '/' || /^\/(seal|runs)\//.test(path);
    if (!isPage) return messagePage('Not found', 'There is nothing at this address.', 404);
    const sessionNonce = await session(request);
    if (!sessionNonce) {
      if (method !== 'GET') return messagePage('Signed out', 'Sign in again, then repeat your decision.', 401);
      return redirect(`/login${path === '/' ? '' : `?next=${encodeURIComponent(path)}`}`);
    }
    if (path === '/' && method === 'GET') return inboxPage(await engine.inbox(ctx));
    if ((m = path.match(/^\/runs\/([^/]+)$/)) && method === 'GET') return runPage(await engine.status(ctx, m[1]));
    if ((m = path.match(/^\/seal\/([A-Za-z0-9_]{1,64})$/))) {
      const approvalId = m[1];
      if (method === 'GET') {
        const { approval, view } = await engine.sealView(ctx, approvalId);
        return sealPage(approval, view, await formToken(need('SESSION_SECRET'), sessionNonce, approvalId));
      }
      if (method === 'POST') {
        sameOrigin(request, url);
        const form = await readForm(request);
        if (!(await checkFormToken(need('SESSION_SECRET'), sessionNonce, approvalId, form.get('t') ?? ''))) {
          return messagePage('Form expired', 'Reload the seal page and decide again.', 403, true);
        }
        const decision = form.get('decision');
        if (decision !== 'seal' && decision !== 'refuse') return messagePage('No decision', 'Choose Seal or Refuse.', 400, true);
        try {
          await engine.decide(ctx, approvalId, decision, form.get('note'));
        } catch (e) {
          if (e instanceof HttpError && e.status === 409) return messagePage('Already decided', 'This request is no longer waiting. Open it to see the decision.', 409, true);
          throw e;
        }
        return redirect(`/seal/${approvalId}`);
      }
    }
    return messagePage('Not found', 'There is nothing at this address.', 404, true);
  }

  return {
    async fetch(request: Request): Promise<Response> {
      try {
        return withSecurity(await route(request));
      } catch (e) {
        const url = new URL(request.url);
        const wantsHtml = !url.pathname.startsWith('/api/') && url.pathname !== '/mcp' && !url.pathname.startsWith('/.well-known/') && url.pathname !== '/health';
        if (wantsHtml && e instanceof HttpError) return withSecurity(messagePage(e.code === 'NOT_FOUND' ? 'Not found' : 'Refused', e.message, e.status));
        const res = errorResponse(e); // logs anything unexpected
        if (wantsHtml) return withSecurity(messagePage('Something went wrong', 'Nothing was decided. Reload the page and try again.', res.status));
        return withSecurity(res);
      }
    },
  };
}
