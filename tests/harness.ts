// Runs the real Worker (createApp) over node:sqlite with a controllable clock, a fresh Ed25519 key and a known
// operator password. Every test talks HTTP to it, the way an agent and a phone would.

import { createApp } from '../src/worker/app';
import { hashPassword } from '../src/core/password';
import { createTestDb } from './d1';

export const ORIGIN = 'https://seal.test';
export const AGENT_KEY = 'test-agent-key-0123456789abcdef';
export const PASSWORD = 'correct horse battery staple';

export async function makeHarness() {
  const db = createTestDb();
  let t = Date.parse('2026-11-03T10:00:00.000Z');
  const now = () => new Date(t).toISOString();
  const advance = (ms: number) => { t += ms; };
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const jwk = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey));
  const env = {
    DB: db, SEAL_ENV: 'test', SEAL_AGENT_KEY: AGENT_KEY,
    SEAL_OPERATOR_HASH: await hashPassword(PASSWORD, undefined, 10_000),
    SESSION_SECRET: 'test-session-secret-0123456789', SEAL_SIGNING_JWK: jwk,
  };
  const app = createApp(env, { now });

  const agent = async (path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST', key = AGENT_KEY) => {
    const res = await app.fetch(new Request(ORIGIN + path, {
      method, headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    }));
    const text = await res.text();
    let data: any = null;
    try { data = JSON.parse(text); } catch { data = text; }
    return { status: res.status, data, headers: res.headers };
  };

  let cookie = '';
  const login = async (password = PASSWORD, ip = '203.0.113.7') => {
    const res = await app.fetch(new Request(ORIGIN + '/login', {
      method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': ip },
      body: new URLSearchParams({ password, next: '/' }).toString(),
    }));
    const set = res.headers.get('set-cookie') ?? '';
    if (res.status === 303) cookie = set.split(';')[0];
    return res;
  };
  const page = (path: string, init: RequestInit = {}) =>
    app.fetch(new Request(ORIGIN + path, { ...init, headers: { cookie, ...(init.headers as Record<string, string> ?? {}) } }));

  /** Opens the seal page, reads its form token, and posts a decision as a phone would. */
  const decide = async (approvalId: string, decision: 'seal' | 'refuse', note = '', headers: Record<string, string> = { origin: ORIGIN }) => {
    const html = await (await page(`/seal/${approvalId}`)).text();
    const token = html.match(/name="t" value="([^"]+)"/)?.[1] ?? '';
    return page(`/seal/${approvalId}`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams({ t: token, decision, note }).toString(),
    });
  };

  return { app, db, env, now, advance, agent, login, page, decide, jwk };
}

export const sampleRun = (agent = 'claude-code@test') => ({
  agent,
  intent: 'Send the founding-seat invitation to the Forge lead after drafting it.',
  plan: ['Draft the mail', 'Send it once Martial seals it'],
  stop_conditions: ['the mail is sent', 'Martial refuses'],
  actions: [
    { kind: 'draft', summary: 'Draft the invitation mail', input: { to: 'lead@example.com', subject: 'Your seat' } },
    { kind: 'send_email', summary: 'Send the invitation to lead@example.com', input: { to: 'lead@example.com', subject: 'Your seat', body: 'Hello — your seat is ready.' } },
  ],
});
