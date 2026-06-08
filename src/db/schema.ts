import type BetterSqlite3 from "better-sqlite3";

export const DDL = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS incidents (
  id          TEXT PRIMARY KEY,
  timestamp   TEXT NOT NULL,
  tool        TEXT NOT NULL,
  session_id  TEXT NOT NULL DEFAULT '',
  username    TEXT NOT NULL DEFAULT '',
  context     TEXT NOT NULL,
  data_types  TEXT NOT NULL,
  severities  TEXT NOT NULL,
  findings    TEXT NOT NULL,
  action      TEXT NOT NULL,
  approval_id TEXT,
  FOREIGN KEY (approval_id) REFERENCES approvals(id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_action    ON incidents(action);
CREATE INDEX IF NOT EXISTS idx_incidents_tool      ON incidents(tool);

CREATE TABLE IF NOT EXISTS audit_log (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT    NOT NULL,
  type      TEXT    NOT NULL,
  payload   TEXT    NOT NULL,
  prev_hash TEXT    NOT NULL,
  hash      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(seq);

CREATE TABLE IF NOT EXISTS approvals (
  id           TEXT    PRIMARY KEY,
  incident_id  TEXT    NOT NULL,
  scope        TEXT    NOT NULL,
  justification TEXT   NOT NULL,
  status       TEXT    NOT NULL DEFAULT 'pending',
  token        TEXT    NOT NULL UNIQUE,
  requested_at TEXT    NOT NULL,
  resolved_at  TEXT,
  resolved_by  TEXT,
  ttl_seconds  INTEGER NOT NULL DEFAULT 3600,
  expires_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_scope_status ON approvals(scope, status);
CREATE INDEX IF NOT EXISTS idx_approvals_expires_at   ON approvals(expires_at);
CREATE INDEX IF NOT EXISTS idx_approvals_status       ON approvals(status);

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_version(version, applied_at) VALUES(1, datetime('now'));

CREATE TABLE IF NOT EXISTS custom_detectors (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  description   TEXT NOT NULL DEFAULT '',
  regex         TEXT NOT NULL UNIQUE,
  severity      TEXT NOT NULL DEFAULT 'high',
  action        TEXT NOT NULL DEFAULT 'block',
  created_at    TEXT NOT NULL,
  examples_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_custom_detectors_created ON custom_detectors(created_at DESC);
`;

export function applySchema(db: BetterSqlite3.Database): void {
  db.exec(DDL);
  // Migration: add username column to tables created before this version
  const cols = db.prepare("PRAGMA table_info(incidents)").all() as { name: string }[];
  if (!cols.some((c) => c.name === "username")) {
    db.exec("ALTER TABLE incidents ADD COLUMN username TEXT NOT NULL DEFAULT ''");
  }
}
