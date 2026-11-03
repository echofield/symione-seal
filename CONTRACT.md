# SYMIONE SEAL — contract v0.1

The Seal lets an agent prepare its actions while a person decides the irreversible ones. Every step is kept in a ledger that cannot be quietly rewritten.

Grammar: **intent → rules → action → seal → proof → trace**. These are SYMIONE's first steps. Settlement comes later and plugs in as a sealed action kind (`charge_payment`).

Sources revived:
- the OP-CHORE kernel (`01_SYSTEMS/Systems/Realsystems/Opera_final/lib/kernel`): strict plan, 8 calls at most, risky tools pause, cursor resume, redaction;
- tiny_seed (`03_LABS/sql`): an append-only table with triggers;
- MANDATE's canonical JSON and hash chain;
- RDE-Kernel's refusal guard;
- the IPX-001 idea that a card carries its own proof rule;
- the IFAH house pattern (Ed25519 signatures).

## Honest scope

- The Seal is a **gate and a witness**. It does not hold the agent's credentials and does not perform the action.
- It **binds** a decision to the exact action. A receipt carries the SHA-256 of the action's canonical input.
- A downstream tool (a deploy script, a mail gateway) is protected only when it **checks a receipt** before acting. An agent with its own direct credentials can still act without asking. Where no receipt is required, the Seal is advisory, and the ledger records what was asked and what was decided.
- The ledger is tamper-evident: a SHA-256 chain over RFC 8785 canonical JSON. It is not tamper-proof: someone with database access could rewrite the whole chain, but cannot change one past event without breaking every later hash. Receipts are signed. Chain heads are not signed yet.

## Actors and authentication

| Actor | How they authenticate | What they can do |
|---|---|---|
| Agent | `Authorization: Bearer <SEAL_AGENT_KEY>` (compared in constant time through SHA-256) | open runs, ask `next`, report, read runs, redeem receipts, verify the ledger, MCP |
| Operator (the person) | password → PBKDF2-SHA256 hash in `SEAL_OPERATOR_HASH` → session cookie (HMAC-SHA256, `SESSION_SECRET`, 12 h, HttpOnly, Secure, SameSite=Lax so a seal link opened from another app arrives signed in; POSTs are protected by the Origin check and the form token) | inbox, seal page, seal or refuse, run pages |
| Anyone | none | `GET /.well-known/symione-seal.json` (public key), `GET /health` |

- **Login lockout:** after 5 failed logins from one source in 15 minutes, the response is `429` until the window passes.
  - The attempt is recorded before it is counted, so a burst of concurrent attempts cannot slip past the limit.
  - There is no global limit, which would let anyone lock the operator out. The password is about 124 random bits.
- **Sessions are stateless.** "Sign out" clears the cookie only. Rotating `SESSION_SECRET` (`make-secrets --remote`) ends every session.
- **Operator POSTs:** they must carry an `Origin` equal to the Seal's own origin, plus a form token (an HMAC of session and approval).

## Policy (rules)

| Risk | Kinds | What happens |
|---|---|---|
| `read` | `read`, `search`, `fetch` | `next` answers **go** |
| `safe` | `draft`, `write_local`, `test`, `preview_deploy`, `note` | `next` answers **go** |
| `sealed` | `send_email`, `send_message`, `deploy_production`, `push_main`, `publish`, `charge_payment`, `delete_data`, `sign_agreement` | `next` opens a seal request and answers **wait** until a person decides |

Limits:
- An unknown kind refuses the whole plan (`400 UNKNOWN_KIND`).
- A run has 1 to 8 actions.
- `intent` is at most 500 characters, each `summary` at most 300, each action `input` at most 16 KB of canonical JSON.
- **Refusal guard:** an agent label holds at most 3 runs in `open` or `waiting_seal`. Labels are self-declared, so there is also a total cap of 20 open runs. Either cap gives `409 TOO_MANY_OPEN_RUNS`, counted inside the transaction.
- At most 10 seal requests wait at once, across all runs. One more gives `429 TOO_MANY_WAITING`, so a flood cannot bury the person.
- A seal request expires 24 h after it opens. A receipt expires 15 minutes after the seal and can be used once.
- An `open` run with no activity for 24 h stops with reason `abandoned`.
- **A sealed action is shown in full.** If its input or summary contains anything the redactor would hide, the run is refused (`400 SECRET_IN_SEALED_INPUT`), because the person must be able to read everything they seal. Pass secrets by name instead (`"env:STRIPE_KEY"`).
- A `__proto__` member anywhere in an input or in evidence is refused (`400`). It would otherwise vanish from the hash.

## States

- Run: `open` → `waiting_seal` → `open` … → `completed`. Or `stopped`, which happens on a refusal, an expired request or a failed action.
- Action: `planned` → `cleared` (read or safe) → `done` or `failed`.
- Action, when sealed: `planned` → `waiting_seal` → `sealed` → `done` or `failed`. Or `refused`, or `expired`.
- A run holds a `cursor`, the index of the current action. `report` moves it forward. Actions run in order.

## Agent API (JSON)

### `POST /api/runs`

Request:

```json
{ "agent": "claude-code@martial-pc", "intent": "…", "plan": ["…"],
  "actions": [{ "kind": "draft", "summary": "…", "input": {} }],
  "stop_conditions": ["…"] }
```

Response `201`:

```json
{ "run_id", "status": "open", "cursor": 0,
  "actions": [{ "index", "kind", "risk", "status": "planned", "input_hash" }],
  "links": { "run": "<origin>/runs/<id>" } }
```

- `input_hash` = `sha256:` + hex(SHA-256(canonical(jsonSafe(input)))).
- The stored input is redacted. The hash is taken over the original.

### `POST /api/runs/:id/next`

Response `200`, one of:

- `{ "decision": "go", "index", "kind", "input_hash" }` for a read or safe action.
- `{ "decision": "go", "index", "kind", "input_hash", "receipt" }` for a sealed action.
- `{ "decision": "wait", "index", "kind", "approval_id", "seal_url", "expires_at" }`. Show `seal_url` to the person and ask again later. Repeated calls give the same answer.
- `{ "decision": "stop", "index", "reason": "refused" | "expired" | "receipt_expired" | "failed" | "late" | "abandoned", "note" }`.
  - `index` is the action that stopped the run.
  - For a refusal, `note` is the person's note. For any other reason, it is a fixed explanation.
- `{ "decision": "done" }`, when every action is reported.

### `POST /api/runs/:id/report`

Request:

```json
{ "index", "outcome": "done" | "failed", "evidence": { … }, "receipt"? }
```

Rules:
- `index` must equal the cursor, and the action must be `cleared` or `sealed`.
- For a sealed action, `evidence` must be a non-empty object (a URL, a message id, a version id…). This is the **proof**.
- Also for a sealed action, the receipt must be the one issued for this action. Reporting `done` redeems it, unless a downstream tool already did.
- **Late reports:** a sealed `done` reported after its receipt expired, with no redeem before expiry, is still recorded, because the act may have happened. The response carries `late: true`, and the run stops with reason `late` instead of completing.
- `failed` stops the run. The cursor stays on the action that stopped the run.

Response `200`:

```json
{ "run_id", "status", "cursor", "late", "next": "next" | "done" | "stopped" }
```

### `GET /api/runs/:id`

Returns the run, its actions (input redacted), its approvals and its ledger events.

### `GET /api/policy`

Returns the kinds, their risks and the limits.

### `POST /api/receipts/redeem`

Request: `{ "receipt", "input_hash", "kind", "run_id"? }`.

- `kind` is the action the downstream tool is about to perform. A receipt sealed for `send_email` never opens a `deploy_production`.
- `200 { "ok": true, "receipt_id", "run_id", "index", "kind" }` when the signature is valid, the kind and the hash match, the receipt has not expired and has not been redeemed before.
- Otherwise `409` with one of: `RECEIPT_INVALID`, `RECEIPT_MISMATCH`, `RECEIPT_EXPIRED`, `RECEIPT_USED`.

### `GET /api/ledger/verify`

Returns `{ "intact", "count", "head": { seq, hash, at } | null, "broken_at_seq", "reason", "method" }`.

### Errors

Every error has the shape `{ "error": { "code", "message" } }`, with the matching HTTP status.

## Receipt

- Payload, in canonical JSON:

  ```json
  { "v": 1, "type": "symione.seal.receipt", "receipt_id", "run_id", "index", "kind", "input_hash",
    "sealed_by": "operator", "sealed_at", "expires_at", "issuer": "<origin>" }
  ```

- Token: `base64url(canonical(payload)) + "." + base64url(Ed25519 signature over those canonical bytes)`.
- The key is the private Ed25519 JWK in `SEAL_SIGNING_JWK`. The public JWK is published at `/.well-known/symione-seal.json`.
- `clients/seal.mjs verify <kind> <receipt> <input.json>` checks the signature, the kind, the hash and the expiry offline, then redeems the receipt online.
- `clients/seal.mjs run <kind> "<summary>" "<command line>"` seals the exact command-line string. After the seal it hands that same string to the shell, so what the person reads is what runs.

## Operator pages (HTML, no script, phone first)

- `GET /`: the inbox, with waiting seals first and then the last 20 runs. It redirects to `/login` without a session.
- `GET /login` and `POST /login`: sign in. `POST /logout`: sign out.
- `GET /seal/:approval_id`: shows the intent, the plan, the action kind, its summary, the redacted input, the input hash, the earlier actions and their evidence, the expiry, and SEAL / REFUSE with an optional note (500 characters at most).
- `POST /seal/:approval_id`: records the decision as a guarded transition, so a request is decided only once (`409` otherwise).
- `GET /runs/:id`: the run and its part of the ledger.
- Security headers on every response:
  - `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`
  - `Referrer-Policy: no-referrer`
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: no-store`

## MCP (`POST /mcp`, agent key)

- Transport: Streamable HTTP, JSON responses only, single requests (no batches).
- Methods: `initialize`, `notifications/initialized` (answered `202`), `ping`, `tools/list`, `tools/call`.
- `GET /mcp` answers `405`.
- Tools, which map onto the API above:
  - `seal_policy`
  - `seal_open_run`
  - `seal_next`
  - `seal_report`
  - `seal_status`
- Each result gives `content: [{ type: "text", text: <JSON> }]` and `structuredContent`. An API error becomes `isError: true`.

## Ledger events (action names)

`run.opened`, `action.cleared`, `seal.requested`, `seal.granted`, `seal.refused`, `seal.expired`, `receipt.redeemed`, `action.done`, `action.failed`, `run.completed`, `run.stopped`.

Each event commits in the same D1 batch as its state change. Table `events` is append-only: triggers abort any UPDATE or DELETE.

## Out of scope for v0.1 (next)

- Settlement on symione-pay (`charge_payment` is only gated for now).
- A Claude proof judge (the symi-one adjudicator ladder).
- Signed chain heads.
- More than one operator.
- Push notifications (for now the agent shows the seal link).
- **The Pact**: several people sealing one shared run. See `docs/NEXT-PROMPT.md`.
