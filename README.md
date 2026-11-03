# SYMIONE SEAL

An agent prepares its actions. A person seals the irreversible ones on their phone. A hash-chained ledger records every step.

`intent → rules → action → seal → proof → trace`

The full rules are in [CONTRACT.md](CONTRACT.md).

## What it does

- An agent opens a **run**: an intent plus 1 to 8 actions, each of a kind from the policy.
- **Read** and **safe** kinds (`read`, `search`, `draft`, `write_local`, `test`, `preview_deploy`…) go straight through.
- **Sealed** kinds wait for the operator: `send_email`, `send_message`, `deploy_production`, `push_main`, `publish`, `charge_payment`, `delete_data`, `sign_agreement`.
  - The agent gets a seal link.
  - The person opens it, reads the exact input, and taps **Seal** or **Refuse**.
- A seal issues an **Ed25519-signed receipt**.
  - It is bound to the SHA-256 of that exact input, valid for 15 minutes, and usable once.
  - A downstream tool checks it before acting (`clients/seal.mjs verify`).
- The agent reports each action. Sealed actions need **evidence** (a URL, a message id, a version id).
- Every transition and its ledger event land in one D1 transaction. The `events` table refuses UPDATE and DELETE, and `/api/ledger/verify` recomputes the chain.

Honest scope: the Seal gates and records; it does not hold the agent's credentials. A tool is protected only where it requires a receipt. Everywhere else the Seal is advisory, and the ledger shows what was asked and what was decided.

## Use it

### From any shell or script

```sh
export SEAL_URL=https://symione-seal.<account>.workers.dev SEAL_AGENT_KEY=…   # from private/SEAL_SECRETS.txt
node clients/seal.mjs run deploy_production "Go live: TONEHOLD 5103496" "npx wrangler deploy --config …"
```

This prints the seal link and waits. Once you seal it on your phone, it runs that exact command line and records the exit code and the last lines of output as evidence.

### From Claude Code (MCP)

```sh
claude mcp add --transport http seal https://symione-seal.<account>.workers.dev/mcp --header "Authorization: Bearer <SEAL_AGENT_KEY>"
```

This adds five tools: `seal_policy`, `seal_open_run`, `seal_next`, `seal_report`, `seal_status`. The server's instructions tell the agent never to perform a sealed kind without a `go` that carries a receipt.

### From a downstream tool (enforcement)

```sh
node clients/seal.mjs verify send_email "$RECEIPT" input.json && actually_send_the_mail
```

`verify` checks the signature against the published key (`/.well-known/symione-seal.json`), then that the receipt was sealed for this kind and this exact input, then the expiry, then redeems the receipt once.

## Develop

```sh
npm install                                  # NODE_OPTIONS=--use-system-ca on this machine
npm test                                     # 15 tests: the Worker over node:sqlite, real HTTP
npx tsc -p tsconfig.json
node scripts/make-secrets.mjs --local        # .dev.vars + private/SEAL_LOCAL.txt
npx wrangler d1 migrations apply symione-seal --local
npx wrangler dev --port 8799
node scripts/smoke.mjs http://127.0.0.1:8799 private/SEAL_LOCAL.txt   # 17 end-to-end checks
```

## Deploy (Cloudflare)

```sh
npx wrangler d1 create symione-seal --jurisdiction eu    # put the id in wrangler.jsonc
npx wrangler d1 migrations apply symione-seal --remote
npx wrangler deploy
node scripts/make-secrets.mjs --remote                    # writes private/SEAL_SECRETS.txt (password + agent key)
node scripts/smoke.mjs https://symione-seal.<account>.workers.dev private/SEAL_SECRETS.txt
```

Running `make-secrets --remote` again rotates everything: old receipts stop verifying and every session ends.

## Sources revived

| Part | From |
|---|---|
| Strict plan, risk allowlist, cursor + pause + approvals, redaction | OP-CHORE kernel, `01_SYSTEMS/Systems/Realsystems/Opera_final/lib/kernel` |
| Append-only events with triggers | tiny_seed, `03_LABS/sql/003_tiny_seed_append_only.sql` |
| Canonical JSON, hash chain, one-batch commit, PBKDF2 | MANDATE, `02_PROJECTS/mandate/src` |
| One-active-commitment refusal guard (here: 3 open runs) | `02_PROJECTS/RDE-Kernel` |
| A card that carries its own proof rule | `02_PROJECTS/IPX-001` |
| Release / return / review with a judge (next step) | `02_PROJECTS/symi-one` Proof v0 |
