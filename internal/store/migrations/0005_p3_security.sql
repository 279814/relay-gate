-- schema 5: security findings + SMTP config (§14 / docs/07).
-- Additive only; schema_version bump is applied by the Go migrator after validation.

CREATE TABLE IF NOT EXISTS security_finding (
  id TEXT PRIMARY KEY,
  at_ms INTEGER NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  summary TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  upstream TEXT NOT NULL DEFAULT '',
  route_id INTEGER NOT NULL DEFAULT 0,
  req_id TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'passive',
  scanner_version TEXT NOT NULL DEFAULT '',
  rule_version TEXT NOT NULL DEFAULT '',
  bytes_scanned INTEGER NOT NULL DEFAULT 0,
  incomplete_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sec_finding_at ON security_finding (at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_sec_finding_sev ON security_finding (severity, at_ms DESC);

CREATE TABLE IF NOT EXISTS smtp_config (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  enabled INTEGER NOT NULL DEFAULT 0,
  host TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 587,
  use_starttls INTEGER NOT NULL DEFAULT 1,
  use_smtps INTEGER NOT NULL DEFAULT 0,
  from_addr TEXT NOT NULL DEFAULT '',
  recipients TEXT NOT NULL DEFAULT '',
  username TEXT NOT NULL DEFAULT '',
  password_enc BLOB,
  min_severity TEXT NOT NULL DEFAULT 'critical',
  updated_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO smtp_config (singleton, updated_at) VALUES (1, 0);
