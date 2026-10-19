CREATE TABLE canary_policy (
    upstream_id INTEGER PRIMARY KEY REFERENCES upstream(id) ON DELETE CASCADE,
    route_id INTEGER NOT NULL REFERENCES route(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
    interval_sec INTEGER NOT NULL DEFAULT 3600 CHECK (interval_sec BETWEEN 300 AND 86400),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1)
);
CREATE TABLE canary_execution (
    execution_id TEXT PRIMARY KEY NOT NULL REFERENCES probe_execution(id) ON DELETE CASCADE CHECK (length(execution_id) BETWEEN 1 AND 64),
    source TEXT NOT NULL CHECK (source IN ('manual','periodic')),
    policy_revision INTEGER NOT NULL CHECK ((source='manual' AND policy_revision=0) OR (source='periodic' AND policy_revision>=1)),
    expectation_version INTEGER NOT NULL CHECK (expectation_version=1),
    nonce_sha256 TEXT NOT NULL CHECK (length(nonce_sha256)=64 AND nonce_sha256 NOT GLOB '*[^0-9a-f]*'),
    expected_tool TEXT NOT NULL CHECK (expected_tool='relay_canary_noop'),
    verdict TEXT NOT NULL CHECK (verdict IN ('passed','violation','incomplete','canceled','execution_failed','not_sent')),
    nonce_matched INTEGER CHECK (nonce_matched IN (0,1)),
    tool_matched INTEGER CHECK (tool_matched IN (0,1)),
    input_usage_present INTEGER NOT NULL DEFAULT 0 CHECK (input_usage_present IN (0,1)),
    output_usage_present INTEGER NOT NULL DEFAULT 0 CHECK (output_usage_present IN (0,1)),
    evidence_hash TEXT NOT NULL CHECK (length(evidence_hash)=64 AND evidence_hash NOT GLOB '*[^0-9a-f]*'),
    CHECK (verdict!='passed' OR (nonce_matched IS 1 AND tool_matched IS 1))
);
CREATE INDEX idx_canary_execution_source ON canary_execution(source,execution_id);
CREATE TABLE canary_cost_daily (
    day_utc TEXT NOT NULL CHECK (length(day_utc)=10),
    source TEXT NOT NULL CHECK (source IN ('manual','periodic')),
    endpoint TEXT NOT NULL CHECK (endpoint IN ('messages','responses','chat_completions')),
    route_id INTEGER NOT NULL CHECK (route_id>0),
    upstream_id INTEGER NOT NULL CHECK (upstream_id>0),
    executions INTEGER NOT NULL DEFAULT 0 CHECK (executions>=0),
    requests INTEGER NOT NULL DEFAULT 0 CHECK (requests>=0),
    passed INTEGER NOT NULL DEFAULT 0 CHECK (passed>=0),
    violated INTEGER NOT NULL DEFAULT 0 CHECK (violated>=0),
    incomplete INTEGER NOT NULL DEFAULT 0 CHECK (incomplete>=0),
    canceled INTEGER NOT NULL DEFAULT 0 CHECK (canceled>=0),
    execution_failed INTEGER NOT NULL DEFAULT 0 CHECK (execution_failed>=0),
    not_sent INTEGER NOT NULL DEFAULT 0 CHECK (not_sent>=0),
    estimated_input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (estimated_input_tokens>=0),
    observed_output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (observed_output_tokens>=0),
    unknown_input_rows INTEGER NOT NULL DEFAULT 0 CHECK (unknown_input_rows>=0),
    unknown_output_rows INTEGER NOT NULL DEFAULT 0 CHECK (unknown_output_rows>=0),
    PRIMARY KEY (day_utc,source,endpoint,route_id,upstream_id)
);
ALTER TABLE probe_cost_event ADD COLUMN canary_source TEXT NOT NULL DEFAULT '' CHECK (canary_source IN ('','manual','periodic'));

