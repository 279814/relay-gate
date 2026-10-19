-- schema 10: bounded passive scan metadata. Historical rows remain unknown.
-- schema_version is written last by the migrator after backup and validation.
ALTER TABLE security_finding ADD COLUMN truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0,1));
ALTER TABLE security_finding ADD COLUMN decode_depth INTEGER NOT NULL DEFAULT 0 CHECK (decode_depth BETWEEN 0 AND 2);
ALTER TABLE security_finding ADD COLUMN evidence_hash TEXT NOT NULL DEFAULT '';
