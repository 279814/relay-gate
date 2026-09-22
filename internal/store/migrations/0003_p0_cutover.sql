-- Schema version 3 cutover (P0-17).
-- Go migrator takes an independent schema2→3 backup, runs validators, then
-- executes this script and Go-side cutover DML in one transaction. The
-- migrator writes schema_version=3 as the final SQL before COMMIT.

INSERT INTO setting(key, value, updated_at)
VALUES ('p0_cutover', 'schema3', strftime('%s','now')*1000)
ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at;

DELETE FROM setting WHERE key = 'probe_cost_today';

UPDATE upstream SET probe_headers = '' WHERE probe_headers IS NOT NULL AND probe_headers != '';

CREATE INDEX IF NOT EXISTS idx_route_model_priority_id
  ON route(model_name_id, priority, id);
