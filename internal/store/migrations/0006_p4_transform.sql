-- schema 6: transform set / version / binding persistence (§15 / docs/08).

CREATE TABLE IF NOT EXISTS transform_set (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  draft_json TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS transform_version (
  id INTEGER PRIMARY KEY,
  set_id INTEGER NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  rules_json TEXT NOT NULL DEFAULT '[]',
  req_fail_policy TEXT NOT NULL DEFAULT 'fail_closed',
  res_fail_policy TEXT NOT NULL DEFAULT 'fail_open',
  note TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (set_id) REFERENCES transform_set(id)
);
CREATE INDEX IF NOT EXISTS idx_xform_ver_set ON transform_version (set_id, id);

CREATE TABLE IF NOT EXISTS transform_binding (
  route_id INTEGER NOT NULL,
  endpoint_id INTEGER NOT NULL,
  set_id INTEGER NOT NULL,
  published_id INTEGER NOT NULL DEFAULT 0,
  shadow_id INTEGER NOT NULL DEFAULT 0,
  revision INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (route_id, endpoint_id),
  FOREIGN KEY (set_id) REFERENCES transform_set(id)
);
