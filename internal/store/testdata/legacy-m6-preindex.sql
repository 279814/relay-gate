-- Apply after legacy-m6-precolumn.sql. This is the crash point after the
-- additive column DDL and before idx_sample_req was created.
ALTER TABLE sample ADD COLUMN req_id TEXT NOT NULL DEFAULT '';
