-- Apply after legacy-m6-preindex.sql. This is the complete M6 upgrade path.
CREATE INDEX IF NOT EXISTS idx_sample_req ON sample (req_id);
