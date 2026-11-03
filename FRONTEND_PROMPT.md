# Handoff — the designed SEAL operator pages (for the design session)

The SYMIONE UI rule applies: this session built the backend and functional pages, and the designed version is yours.

## Target

`Desktop/02_PROJECTS/symione-seal/src/worker/pages.ts`.

- The pages are server-rendered HTML strings with no script.
- CSP: `default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`. That means inline `<style>` only, no external fonts, images or scripts.
- If you need a web font, propose serving it from the Worker itself and widening the CSP to `font-src 'self'`.

## Lane

Internal/operator: paper-cream. Tokens are in memory `reference-symione-platform-tokens`:
- surfaces: paper `#F7F5EF`, paper-dark `#F0EDE5`, card `#FBFAF7`, border `#E7E2D8`;
- ink: ink `#1F1F1A`, muted `#7D7A70`, faint `#A8A49A`;
- accents: green `#365C4A`, red `#C86A5A`;
- type: Instrument Serif for heads, Inter for body, mono for hashes.

## Pages, with the data each gets (see `pages.ts`; shapes come from `engine.status()` / `engine.inbox()`)

1. **Login** `/login`: a single password field.
2. **Inbox** `/`: waiting seal requests (kind, summary, agent, intent, expires_at), then the last 20 runs (agent, intent, status, cursor/action_count).
3. **Seal** `/seal/:id`: the heart of it. This page is read on a phone, often at night. It shows:
   - the agent and the action summary as the headline;
   - the kind;
   - the exact input as pretty JSON;
   - the input hash;
   - the SEAL and REFUSE buttons with an optional note;
   - the expiry;
   - then the why (intent, plan, stop conditions), the whole run's actions with their status and evidence, and the run's ledger events (seq, action, actor, time, hash).

   Once decided, the form disappears and the decision block shows (status, who, when, note).
4. **Run** `/runs/:id`: the run, its actions and its ledger.

## Constraints

- Keep every interpolation through `esc()`.
- Keep the form fields (`t`, `decision`, `note`) and the POST targets.
- Run `npm test` and `node scripts/smoke.mjs` afterwards: the smoke reads `name="t" value="…"` from the seal page.
- Copy voice: affirmative and present tense (see the `symione` skill).
