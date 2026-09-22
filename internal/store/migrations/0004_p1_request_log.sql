-- schema 4: persist request_log duplicate_risk / retry_reason (§11.4 / docs/05).
-- Additive only; schema_version bump is applied by the Go migrator after validation.

ALTER TABLE request_log ADD COLUMN duplicate_risk INTEGER NOT NULL DEFAULT 0;
ALTER TABLE request_log ADD COLUMN retry_reason TEXT NOT NULL DEFAULT '';
