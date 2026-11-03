import { describe, expect, it } from 'vitest';
import { canonical, digest, jsonSafe } from '../src/core/canonical';
import { nextEvent, verifyChain, type ChainEvent } from '../src/core/chain';
import { redact, redactValue } from '../src/core/redact';
import { checkReceipt, publicJwk, signReceipt, importSigningKey, type ReceiptPayload } from '../src/core/receipt';
import { checkSession, issueSession } from '../src/core/session';

describe('canonical + hash', () => {
  it('orders keys and hashes the same value the same way', async () => {
    expect(canonical({ b: 1, a: [true, null, 'x'] })).toBe('{"a":[true,null,"x"],"b":1}');
    expect(await digest(jsonSafe({ b: 1, a: 2 }))).toBe(await digest(jsonSafe({ a: 2, b: 1 })));
    expect(jsonSafe({ x: 1.5 })).toEqual({ x: '1.5' });
  });
});

describe('redaction', () => {
  it('removes known secret shapes and secret-named members', () => {
    const fake = 'sk-proj-' + 'A'.repeat(40);
    expect(redact(`key ${fake} end`)).toBe('key [REDACTED:openai-key] end');
    expect(redact('Bearer abcdefghijklmnopqrstuvwxyz123456')).toBe('Bearer [REDACTED]');
    expect(redact('eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4')).toBe('[REDACTED:jwt]');
    expect(redactValue({ password: 'hunter22', nested: { api_key: 'abc12345' }, ok: 'x' })).toEqual({ password: '[REDACTED]', nested: { api_key: '[REDACTED]' }, ok: 'x' });
  });
  it('keeps domains, versions and file names that the old JWT rule ate', () => {
    for (const s of ['tonehold.ifahinstruments.com', 'v1.2.3', 'report.final.pdf', 'symione-seal.workers.dev']) expect(redact(s)).toBe(s);
  });
});

describe('hash chain', () => {
  it('verifies an intact chain and finds a changed event', async () => {
    const events: ChainEvent[] = [];
    let head = null;
    for (let i = 0; i < 4; i++) {
      const e = await nextEvent(head, { id: `e${i}`, at: `2026-11-03T10:0${i}:00.000Z`, actor: 'a', action: 'x', runId: 'r', payload: { i } });
      events.push(e); head = { seq: e.seq, hash: e.hash, at: e.at };
    }
    expect((await verifyChain(events)).intact).toBe(true);
    events[1] = { ...events[1], payloadJson: '{"i":99}' };
    expect(await verifyChain(events)).toMatchObject({ intact: false, brokenAtSeq: 1 });
  });
});

describe('receipts', () => {
  it('signs, binds to the input hash, expires, and rejects tampering', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const jwk = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey));
    const payload: ReceiptPayload = {
      v: 1, type: 'symione.seal.receipt', receipt_id: 'rcpt_x', run_id: 'run_x', index: 1, kind: 'send_email',
      input_hash: 'sha256:' + 'a'.repeat(64), sealed_by: 'operator', sealed_at: '2026-11-03T10:00:00.000Z',
      expires_at: '2026-11-03T10:15:00.000Z', issuer: 'https://seal.test',
    };
    const token = await signReceipt(await importSigningKey(jwk), payload);
    const pub = publicJwk(jwk);
    expect(pub).not.toHaveProperty('d');
    expect(await checkReceipt(pub, token, payload.input_hash, '2026-11-03T10:05:00.000Z')).toMatchObject({ ok: true });
    expect(await checkReceipt(pub, token, 'sha256:' + 'b'.repeat(64), '2026-11-03T10:05:00.000Z')).toMatchObject({ ok: false, code: 'RECEIPT_MISMATCH' });
    expect(await checkReceipt(pub, token, payload.input_hash, '2026-11-03T10:15:00.000Z')).toMatchObject({ ok: false, code: 'RECEIPT_EXPIRED' });
    const [body, sig] = token.split('.');
    const forged = Buffer.from(Buffer.from(body, 'base64url').toString().replace('send_email', 'push_main__')).toString('base64url');
    expect(await checkReceipt(pub, `${forged}.${sig}`, null, null)).toMatchObject({ ok: false, code: 'RECEIPT_INVALID' });
    const other = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const otherPub = (await crypto.subtle.exportKey('jwk', other.publicKey)) as JsonWebKey;
    expect(await checkReceipt(otherPub, token, null, null)).toMatchObject({ ok: false, code: 'RECEIPT_INVALID' });
  });
});

describe('sessions', () => {
  it('accepts its own token until expiry and rejects others', async () => {
    const t = await issueSession('s3cret-s3cret', 1000);
    expect(await checkSession('s3cret-s3cret', t, 1001)).toBeTruthy();
    expect(await checkSession('s3cret-s3cret', t, 1000 + 12 * 3600)).toBeNull();
    expect(await checkSession('other-secret', t, 1001)).toBeNull();
    expect(await checkSession('s3cret-s3cret', t.replace(/.$/, c => (c === 'A' ? 'B' : 'A')), 1001)).toBeNull();
  });
});

describe('signing key import', () => {
  it('accepts a JWK carrying alg "Ed25519" (Node 25 export) and signs with it', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const jwk = { ...(await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey, alg: 'Ed25519', key_ops: ['sign'], ext: true };
    await expect(importSigningKey(JSON.stringify(jwk))).resolves.toBeTruthy();
    await expect(importSigningKey(JSON.stringify({ ...jwk, d: undefined }))).rejects.toThrow(/private Ed25519/);
  });
});

describe('redaction by member name (review fix)', () => {
  it('catches compound secret names and private JWK members, and leaves look-alikes alone', () => {
    const out = redactValue({
      db_password: 'p4ssw0rd!', AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI', clientSecret: 'cs-123456', apiKey: 'k-123456',
      jwk: { kty: 'OKP', crv: 'Ed25519', x: 'pub', d: 'priv' },
      max_tokens: 1000, secretary_name: 'Ana', note: 'the "password": "hunter2222" is old',
    }) as Record<string, any>;
    expect(out.db_password).toBe('[REDACTED]');
    expect(out.AWS_SECRET_ACCESS_KEY).toBe('[REDACTED]');
    expect(out.clientSecret).toBe('[REDACTED]');
    expect(out.apiKey).toBe('[REDACTED]');
    expect(out.jwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: 'pub', d: '[REDACTED]' });
    expect(out.max_tokens).toBe(1000);
    expect(out.secretary_name).toBe('Ana');
    expect(out.note).not.toContain('hunter2222');
  });
});
