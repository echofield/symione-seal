// Generates the Seal's four secrets and either writes them for local dev or sets them on the deployed Worker.
// Values go to private/ (gitignored) and through stdin to wrangler; they are never printed.
//
//   node scripts/make-secrets.mjs --local    writes .dev.vars (for `wrangler dev`) + private/SEAL_LOCAL.txt
//   node scripts/make-secrets.mjs --remote   sets SEAL_AGENT_KEY, SEAL_OPERATOR_HASH, SESSION_SECRET, SEAL_SIGNING_JWK
//                                            on the deployed Worker; writes private/SEAL_SECRETS.txt (agent key +
//                                            operator password) and private/seal-signing.jwk.json. Re-running rotates
//                                            everything: old receipts stop verifying and every session ends.

import { execFileSync } from 'node:child_process';
import { randomBytes, webcrypto } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';

const ITERATIONS = 100_000; // the Worker's PBKDF2 ceiling; must match src/core/password.ts
const b64url = buf => Buffer.from(buf).toString('base64url');

async function hash(password) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const key = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
  const bits = await webcrypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, key, 256);
  return `pbkdf2-sha256$${ITERATIONS}$${b64url(salt)}$${b64url(new Uint8Array(bits))}`;
}

// Readable on a phone keyboard, strong: 5 groups of 5 from an alphabet without look-alikes (~124 bits).
function password() {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  const chars = [];
  while (chars.length < 25) { const b = randomBytes(1)[0]; if (b < 248) chars.push(alphabet[b % alphabet.length]); }
  return [0, 5, 10, 15, 20].map(i => chars.slice(i, i + 5).join('')).join('-');
}

const mode = process.argv[2];
if (mode !== '--local' && mode !== '--remote') { console.log('Usage: node scripts/make-secrets.mjs --local | --remote'); process.exit(2); }

const pair = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
const jwk = JSON.stringify(await webcrypto.subtle.exportKey('jwk', pair.privateKey));
const operatorPassword = password();
const values = {
  SEAL_AGENT_KEY: 'seal_ak_' + b64url(randomBytes(32)),
  SEAL_OPERATOR_HASH: await hash(operatorPassword),
  SESSION_SECRET: b64url(randomBytes(32)),
  SEAL_SIGNING_JWK: jwk,
};
mkdirSync('private', { recursive: true });

if (mode === '--local') {
  writeFileSync('.dev.vars', Object.entries({ SEAL_ENV: 'local', ...values }).map(([k, v]) => `${k}='${v}'`).join('\n') + '\n');
  writeFileSync('private/SEAL_LOCAL.txt', `Local Seal (wrangler dev)\nOperator password: ${operatorPassword}\nSEAL_AGENT_KEY=${values.SEAL_AGENT_KEY}\n`);
  console.log('Wrote .dev.vars and private/SEAL_LOCAL.txt (local only).');
} else {
  for (const [name, value] of Object.entries(values)) {
    execFileSync(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['--no-install', 'wrangler', 'secret', 'put', name], {
      input: value, stdio: ['pipe', 'inherit', 'inherit'], shell: process.platform === 'win32',
      env: { ...process.env, CI: '1', NODE_OPTIONS: [process.env.NODE_OPTIONS, '--use-system-ca'].filter(Boolean).join(' ') },
    });
  }
  writeFileSync('private/seal-signing.jwk.json', jwk + '\n');
  writeFileSync('private/SEAL_SECRETS.txt', [
    `SYMIONE SEAL — set ${new Date().toISOString()}`,
    `Operator password (phone sign-in): ${operatorPassword}`,
    `SEAL_AGENT_KEY=${values.SEAL_AGENT_KEY}`,
    'The signing key is in private/seal-signing.jwk.json. Keep this folder off git and off shared drives.',
  ].join('\n') + '\n');
  console.log('Secrets set on the Worker. Password and agent key: private/SEAL_SECRETS.txt');
}
