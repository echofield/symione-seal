-- SYMIONE SEAL v0.1 schema. State tables change; the events table is the trace and only ever grows.

CREATE TABLE runs (
  id TEXT PRIMARY KEY,
  agent TEXT NOT NULL,
  intent TEXT NOT NULL,
  plan_json TEXT NOT NULL,
  stop_conditions_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'waiting_seal', 'completed', 'stopped')),
  cursor INTEGER NOT NULL DEFAULT 0,
  action_count INTEGER NOT NULL CHECK (action_count BETWEEN 1 AND 8),
  stop_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  ended_at TEXT
);
CREATE INDEX runs_agent_status ON runs (agent, status);
CREATE INDEX runs_created ON runs (created_at DESC);

CREATE TABLE actions (
  run_id TEXT NOT NULL REFERENCES runs (id),
  idx INTEGER NOT NULL,
  kind TEXT NOT NULL,
  risk TEXT NOT NULL CHECK (risk IN ('read', 'safe', 'sealed')),
  summary TEXT NOT NULL,
  input_json TEXT NOT NULL,          -- redacted for display; the hash below is over the original input
  input_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('planned', 'cleared', 'waiting_seal', 'sealed', 'refused', 'expired', 'done', 'failed')),
  evidence_json TEXT,
  reported_at TEXT,
  PRIMARY KEY (run_id, idx)
);

CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs (id),
  idx INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('waiting', 'sealed', 'refused', 'expired')),
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by TEXT,
  note TEXT,
  UNIQUE (run_id, idx)
);
CREATE INDEX approvals_status ON approvals (status, requested_at);

CREATE TABLE receipts (
  id TEXT PRIMARY KEY,
  approval_id TEXT NOT NULL UNIQUE REFERENCES approvals (id),
  run_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  kind TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  token TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  redeemed_at TEXT,
  redeemed_by TEXT
);

CREATE TABLE events (
  seq INTEGER PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  run_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX events_run ON events (run_id, seq);

-- The trace only grows (pattern from 03_LABS/sql/003_tiny_seed_append_only.sql).
CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only: UPDATE is forbidden'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only: DELETE is forbidden'); END;

-- A guarded transition inserts a 0 here when the UPDATE before it changed no row; the CHECK fails, the whole D1
-- batch rolls back, and the request gets a 409. No row ever persists in this table.
CREATE TABLE guards (ok INTEGER CONSTRAINT seal_guard CHECK (ok = 1));

CREATE TABLE login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  ok INTEGER NOT NULL,
  ip TEXT NOT NULL
);
CREATE INDEX login_attempts_at ON login_attempts (at);
