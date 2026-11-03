# Next session — THE PACT on top of THE SEAL

Open from `C:\Users\echof` (shared memory). Read first:
- `Desktop/02_PROJECTS/symione-seal/CONTRACT.md` and `README.md`: the Seal v0.1, built and deployed 3 Nov 2026;
- `Desktop/ARCHIVE-REVIVAL-2026-11-03.md` §4 (THE PACT);
- `Desktop/BUILD-METHOD.md`.

## Goal

A **pact** is a finite commitment shared by several people: a four-week Lobster residency, a season, a challenge. It has proofs, a sealed outcome, and a failure artifact if it fails.

It is the Seal widened to many people:
- the Seal's run becomes the pact;
- its actions become the commitments;
- the single operator becomes the members, each sealing their own part;
- the Seal's receipt and ledger are reused as they are.

## Material to revive (read before designing)

- `02_PROJECTS/Community-Kernel/community-kernel`: CELL, 9 Postgres migrations (cells, cell_members, cell_commitments, append-only cell_events, cell_proofs, artifacts, the seal and the failure artifact, deadlines), and `docs/CONSTITUTION.md`: finite execution, append-only truth, money kept apart from truth, a failure emits an artifact, no new cycle without re-consent.
- `02_PROJECTS/factory-of-culture-kernel`: patterns, forks and licences, FailureArtifact, the 7 template families (`FACTORYOFCULTURE/data.js` has their content).
- `02_PROJECTS/reliable-temp`: the challenge → proof → review → payout screens (a reference only; rebuild on the Seal).
- `02_PROJECTS/field-backend/src/split.ts`: the warm-intro reward split, for a later settlement rule.

## Contract first

Write `CONTRACT.md` for symione-pact. It runs on the same Worker + D1 stack and reuses the Seal's `src/core` (canonical JSON, chain, receipt, redaction, session). It covers:
- members who sign in with magic links. Mail is production-class on this machine: prepare the link, and Martial sends it.
- a pact with a deadline and commitments per member;
- a proof per commitment, sealed by a designated witness member;
- an outcome sealed at the deadline: kept, or failed with its failure artifact;
- forking a pact pattern.

Settlement stays outside v0.1, as in the Seal.

## First real use

A four-week Lobster residency: 3 sessions per member, with proof as a session file hash, recorded through Hold where possible.
