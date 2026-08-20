-- Schema version 2 expand migration. It is intentionally additive: legacy
-- columns remain byte-for-byte available to the schema-1 reader.

ALTER TABLE upstream ADD COLUMN probe_mode TEXT NOT NULL DEFAULT 'active'
    CHECK (probe_mode IN ('active','lazy'));
ALTER TABLE upstream ADD COLUMN host_override TEXT NOT NULL DEFAULT '';
ALTER TABLE upstream ADD COLUMN tls_server_name TEXT NOT NULL DEFAULT '';
ALTER TABLE upstream ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
ALTER TABLE upstream ADD COLUMN network_revision INTEGER NOT NULL DEFAULT 1 CHECK (network_revision >= 1);
ALTER TABLE upstream ADD COLUMN credential_revision INTEGER NOT NULL DEFAULT 1 CHECK (credential_revision >= 1);

ALTER TABLE model_name ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
ALTER TABLE model_name ADD COLUMN capability_revision INTEGER NOT NULL DEFAULT 1 CHECK (capability_revision >= 1);

ALTER TABLE route ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
ALTER TABLE route ADD COLUMN capability_revision INTEGER NOT NULL DEFAULT 1 CHECK (capability_revision >= 1);

ALTER TABLE setting ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);

CREATE TABLE run_state (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    state      TEXT NOT NULL CHECK (state IN ('running','paused')),
    revision   INTEGER NOT NULL CHECK (revision >= 1),
    updated_at INTEGER NOT NULL
);
INSERT INTO run_state(singleton, state, revision, updated_at)
SELECT 1,
       CASE WHEN COALESCE((SELECT value FROM setting WHERE key='run_state'), 'running') = 'paused'
            THEN 'paused' ELSE 'running' END,
       1, 0;

CREATE TABLE legacy_full_url (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    upstream_id       INTEGER NOT NULL UNIQUE REFERENCES upstream(id) ON DELETE CASCADE,
    url_enc           TEXT NOT NULL,
    masked_url        TEXT NOT NULL,
    fingerprint       TEXT NOT NULL,
    inferred_endpoint TEXT CHECK (inferred_endpoint IS NULL OR inferred_endpoint IN
        ('models','messages','responses','chat_completions','count_tokens')),
    needs_review      INTEGER NOT NULL DEFAULT 1 CHECK (needs_review IN (0,1)),
    revision          INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE upstream_endpoint (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    upstream_id              INTEGER NOT NULL REFERENCES upstream(id) ON DELETE CASCADE,
    endpoint                 TEXT NOT NULL CHECK (endpoint IN
        ('models','messages','responses','chat_completions','count_tokens')),
    url_mode                 TEXT NOT NULL CHECK (url_mode IN ('canonical','legacy_exact')),
    legacy_full_url_id       INTEGER REFERENCES legacy_full_url(id) ON DELETE RESTRICT,
    legacy_full_url_revision INTEGER NOT NULL DEFAULT 0 CHECK (legacy_full_url_revision >= 0),
    legacy_compat_real_only  INTEGER NOT NULL DEFAULT 0 CHECK (legacy_compat_real_only IN (0,1)),
    url_override             TEXT NOT NULL DEFAULT '',
    fixed_query_template     TEXT NOT NULL DEFAULT '',
    auth_mode                TEXT NOT NULL CHECK (auth_mode IN
        ('header_bearer','x_api_key','api_key','fixed_query_secret','manual_headers',
         'auto_calibrated','legacy_auto_real_only')),
    calibrated_mode          TEXT NOT NULL DEFAULT '' CHECK (calibrated_mode IN
        ('','header_bearer','x_api_key','api_key','fixed_query_secret','manual_headers')),
    auth_header_name         TEXT NOT NULL DEFAULT '',
    auth_query_name          TEXT NOT NULL DEFAULT '',
    auth_secret_ref          TEXT NOT NULL DEFAULT 'upstream_api_key',
    auth_manual_headers_json TEXT NOT NULL DEFAULT '[]',
    auth_profile_revision    INTEGER NOT NULL DEFAULT 1 CHECK (auth_profile_revision >= 1),
    revision                 INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    needs_review             INTEGER NOT NULL DEFAULT 0 CHECK (needs_review IN (0,1)),
    created_at               INTEGER NOT NULL,
    updated_at               INTEGER NOT NULL,
    UNIQUE (upstream_id, endpoint),
    CHECK (
        (url_mode='canonical' AND legacy_full_url_id IS NULL AND legacy_full_url_revision=0) OR
        (url_mode='legacy_exact' AND legacy_full_url_id IS NOT NULL AND legacy_full_url_revision>=1
         AND needs_review=1)
    ),
    CHECK (auth_mode!='auto_calibrated' OR calibrated_mode='' OR calibrated_mode IN
        ('header_bearer','x_api_key','api_key','fixed_query_secret','manual_headers')),
    CHECK (auth_mode='legacy_auto_real_only' OR legacy_compat_real_only=0)
);
CREATE INDEX idx_endpoint_upstream_id ON upstream_endpoint(upstream_id, id);
CREATE INDEX idx_endpoint_review_id ON upstream_endpoint(needs_review, id);

CREATE TABLE probe_secret (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    value_enc   TEXT NOT NULL,
    masked      TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    revision    INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
CREATE INDEX idx_probe_secret_name_id ON probe_secret(name, id);

CREATE TABLE probe_recipe (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    upstream_id            INTEGER REFERENCES upstream(id) ON DELETE RESTRICT,
    route_id               INTEGER REFERENCES route(id) ON DELETE RESTRICT,
    endpoint               TEXT NOT NULL CHECK (endpoint IN
        ('models','messages','responses','chat_completions','count_tokens')),
    status                 TEXT NOT NULL CHECK (status IN
        ('draft','published','disabled','archived','legacy_compat','legacy_quarantined')),
    pinned                 INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0,1)),
    draft_version_id       INTEGER,
    published_version_id   INTEGER,
    last_publish_forced    INTEGER NOT NULL DEFAULT 0 CHECK (last_publish_forced IN (0,1)),
    last_test_execution_id TEXT,
    published_at           INTEGER NOT NULL DEFAULT 0,
    revision               INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    active_binding_revision INTEGER NOT NULL DEFAULT 1 CHECK (active_binding_revision >= 1),
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    CHECK ((upstream_id IS NOT NULL) <> (route_id IS NOT NULL))
);
CREATE UNIQUE INDEX idx_recipe_active_upstream_endpoint
    ON probe_recipe(upstream_id, endpoint) WHERE upstream_id IS NOT NULL AND status != 'archived';
CREATE UNIQUE INDEX idx_recipe_active_route_endpoint
    ON probe_recipe(route_id, endpoint) WHERE route_id IS NOT NULL AND status != 'archived';
CREATE INDEX idx_recipe_status_id ON probe_recipe(status, id);

CREATE TABLE probe_recipe_version (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id          INTEGER NOT NULL REFERENCES probe_recipe(id) ON DELETE RESTRICT,
    version            INTEGER NOT NULL CHECK (version >= 1),
    origin             TEXT NOT NULL CHECK (origin IN
        ('manual','learned','compact_native','calibration_native','basic_protocol','legacy_migration')),
    method             TEXT NOT NULL CHECK (method IN ('GET','HEAD','POST')),
    fixed_raw_query    TEXT NOT NULL DEFAULT '',
    headers_json       TEXT NOT NULL DEFAULT '[]',
    body               BLOB,
    body_is_text       INTEGER NOT NULL DEFAULT 0 CHECK (body_is_text IN (0,1)),
    stream_expected    INTEGER NOT NULL DEFAULT 0 CHECK (stream_expected IN (0,1)),
    timeout_profile    TEXT NOT NULL CHECK (timeout_profile IN
        ('l1','l2_standard','l2_long_thinking','count_tokens')),
    created_at         INTEGER NOT NULL,
    UNIQUE (recipe_id, version),
    CHECK ((method IN ('GET','HEAD') AND length(COALESCE(body, X''))=0) OR method='POST')
);
CREATE INDEX idx_recipe_version_recipe_version_id
    ON probe_recipe_version(recipe_id, version, id);

CREATE TRIGGER probe_recipe_version_no_update
BEFORE UPDATE ON probe_recipe_version
BEGIN
    SELECT RAISE(ABORT, 'probe_recipe_version is immutable');
END;
CREATE TRIGGER probe_recipe_version_no_delete
BEFORE DELETE ON probe_recipe_version
BEGIN
    SELECT RAISE(ABORT, 'probe_recipe_version is immutable');
END;

CREATE TABLE recipe_version_required_secret (
    recipe_version_id         INTEGER NOT NULL REFERENCES probe_recipe_version(id) ON DELETE RESTRICT,
    name                      TEXT NOT NULL,
    resolved_secret_id        INTEGER REFERENCES probe_secret(id) ON DELETE SET NULL,
    bound_secret_id_snapshot  INTEGER NOT NULL DEFAULT 0,
    bound_revision_snapshot   INTEGER NOT NULL DEFAULT 0,
    bound_fingerprint_snapshot TEXT NOT NULL DEFAULT '',
    bound_name_snapshot       TEXT NOT NULL,
    PRIMARY KEY (recipe_version_id, name)
);

CREATE TABLE recipe_active_secret_ref (
    recipe_id  INTEGER NOT NULL REFERENCES probe_recipe(id) ON DELETE CASCADE,
    secret_id  INTEGER NOT NULL REFERENCES probe_secret(id) ON DELETE RESTRICT,
    name       TEXT NOT NULL,
    revision   INTEGER NOT NULL CHECK (revision >= 1),
    PRIMARY KEY (recipe_id, name)
);

CREATE TABLE endpoint_active_secret_ref (
    endpoint_id INTEGER NOT NULL REFERENCES upstream_endpoint(id) ON DELETE CASCADE,
    secret_id   INTEGER NOT NULL REFERENCES probe_secret(id) ON DELETE RESTRICT,
    name        TEXT NOT NULL,
    revision    INTEGER NOT NULL CHECK (revision >= 1),
    PRIMARY KEY (endpoint_id, name)
);

CREATE TABLE client_probe_profile (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    upstream_id         INTEGER NOT NULL REFERENCES upstream(id) ON DELETE RESTRICT,
    endpoint            TEXT NOT NULL CHECK (endpoint IN
        ('models','messages','responses','chat_completions','count_tokens')),
    status              TEXT NOT NULL CHECK (status IN ('candidate','tested','disabled')),
    safe_headers_json   TEXT NOT NULL DEFAULT '[]',
    fixed_raw_query     TEXT NOT NULL DEFAULT '',
    query_shape_json    BLOB,
    body_template       BLOB,
    body_shape_json     BLOB,
    client_family       TEXT NOT NULL,
    shape_hash          TEXT NOT NULL,
    revision            INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    last_seen_at        INTEGER NOT NULL,
    seen_count          INTEGER NOT NULL DEFAULT 1 CHECK (seen_count >= 1),
    tested_execution_id TEXT,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    UNIQUE (upstream_id, endpoint, client_family, shape_hash)
);
CREATE UNIQUE INDEX idx_client_profile_tested_endpoint
    ON client_probe_profile(upstream_id, endpoint) WHERE status='tested';
CREATE INDEX idx_client_profile_scope_created
    ON client_probe_profile(upstream_id, endpoint, client_family, created_at DESC, id DESC);

CREATE TABLE client_profile_required_secret (
    client_profile_id          INTEGER NOT NULL REFERENCES client_probe_profile(id) ON DELETE RESTRICT,
    name                       TEXT NOT NULL,
    resolved_secret_id         INTEGER REFERENCES probe_secret(id) ON DELETE SET NULL,
    bound_secret_id_snapshot   INTEGER NOT NULL DEFAULT 0,
    bound_revision_snapshot    INTEGER NOT NULL DEFAULT 0,
    bound_fingerprint_snapshot TEXT NOT NULL DEFAULT '',
    bound_name_snapshot        TEXT NOT NULL,
    PRIMARY KEY (client_profile_id, name)
);

CREATE TABLE client_profile_active_secret_ref (
    client_profile_id INTEGER NOT NULL REFERENCES client_probe_profile(id) ON DELETE CASCADE,
    secret_id         INTEGER NOT NULL REFERENCES probe_secret(id) ON DELETE RESTRICT,
    name              TEXT NOT NULL,
    revision          INTEGER NOT NULL CHECK (revision >= 1),
    PRIMARY KEY (client_profile_id, name)
);

CREATE TABLE probe_execution (
    id                                  TEXT PRIMARY KEY,
    trigger                             TEXT NOT NULL CHECK (trigger IN
        ('scheduled','manual','calibration','recovery','real_traffic')),
    upstream_id                         INTEGER NOT NULL REFERENCES upstream(id) ON DELETE RESTRICT,
    upstream_network_revision           INTEGER NOT NULL,
    upstream_credential_revision        INTEGER NOT NULL,
    reachability_evidence_kind          TEXT NOT NULL DEFAULT '',
    reachability_timeout_profile        TEXT NOT NULL DEFAULT '',
    capability_evidence_kind            TEXT NOT NULL DEFAULT '',
    capability_timeout_profile          TEXT NOT NULL DEFAULT '',
    reachability_settings_fingerprint   TEXT NOT NULL DEFAULT '',
    probe_settings_fingerprint          TEXT NOT NULL DEFAULT '',
    endpoint_id                         INTEGER REFERENCES upstream_endpoint(id) ON DELETE RESTRICT,
    endpoint_revision                   INTEGER NOT NULL DEFAULT 0,
    model_capability_revision           INTEGER NOT NULL DEFAULT 0,
    route_capability_revision           INTEGER NOT NULL DEFAULT 0,
    auth_profile_revision               INTEGER NOT NULL DEFAULT 0,
    probe_secret_revisions_hash         TEXT NOT NULL DEFAULT '',
    request_transform_binding_revision  INTEGER NOT NULL DEFAULT 0,
    route_id                            INTEGER REFERENCES route(id) ON DELETE RESTRICT,
    endpoint                            TEXT NOT NULL CHECK (endpoint IN
        ('models','messages','responses','chat_completions','count_tokens')),
    recipe_binding_use                  TEXT NOT NULL CHECK (recipe_binding_use IN
        ('resolved','explicit_test','explicit_profile_test','real_traffic_context')),
    recipe_id                           INTEGER REFERENCES probe_recipe(id) ON DELETE RESTRICT,
    recipe_version_id                   INTEGER REFERENCES probe_recipe_version(id) ON DELETE RESTRICT,
    recipe_storage                      TEXT NOT NULL CHECK (recipe_storage IN ('db','profile','embedded')),
    recipe_origin                       TEXT NOT NULL CHECK (recipe_origin IN
        ('manual','learned','compact_native','calibration_native','basic_protocol','legacy_migration')),
    client_profile_id                   INTEGER REFERENCES client_probe_profile(id) ON DELETE RESTRICT,
    template_id                         TEXT NOT NULL DEFAULT '',
    recipe_binding_revision             INTEGER NOT NULL DEFAULT 0,
    recipe_identity_revision            INTEGER NOT NULL DEFAULT 0,
    recipe_binding_facts_json           TEXT NOT NULL DEFAULT '{}',
    real_request_shape_hash             TEXT NOT NULL DEFAULT '',
    real_request_shape_learnable        INTEGER NOT NULL DEFAULT 0 CHECK (real_request_shape_learnable IN (0,1)),
    real_request_shape_unavailable_reason TEXT NOT NULL DEFAULT '',
    reachability_token                  TEXT NOT NULL DEFAULT '',
    capability_token                    TEXT NOT NULL DEFAULT '',
    resolved_url_hash                   TEXT NOT NULL DEFAULT '',
    request_url_hash                    TEXT NOT NULL DEFAULT '',
    evidence_hash                       TEXT NOT NULL,
    status_code                         INTEGER NOT NULL DEFAULT 0,
    error_class                         TEXT NOT NULL,
    capability_state                    TEXT NOT NULL,
    observation_scope                   TEXT NOT NULL,
    reachable                           INTEGER NOT NULL DEFAULT 0 CHECK (reachable IN (0,1)),
    final                               INTEGER NOT NULL DEFAULT 0 CHECK (final IN (0,1)),
    success                             INTEGER NOT NULL DEFAULT 0 CHECK (success IN (0,1)),
    semantic_seen                       INTEGER NOT NULL DEFAULT 0 CHECK (semantic_seen IN (0,1)),
    normal_end_seen                     INTEGER NOT NULL DEFAULT 0 CHECK (normal_end_seen IN (0,1)),
    partial                             INTEGER NOT NULL DEFAULT 0 CHECK (partial IN (0,1)),
    candidate_disposition               TEXT NOT NULL DEFAULT '',
    redacted_detail                     TEXT NOT NULL DEFAULT '',
    sent_at_ms                          INTEGER NOT NULL DEFAULT 0,
    tls_handshake_start_at_ms           INTEGER NOT NULL DEFAULT 0,
    tls_handshake_done_at_ms            INTEGER NOT NULL DEFAULT 0,
    got_conn_at_ms                      INTEGER NOT NULL DEFAULT 0,
    response_header_at_ms               INTEGER NOT NULL DEFAULT 0,
    first_byte_at_ms                    INTEGER NOT NULL DEFAULT 0,
    first_event_at_ms                   INTEGER NOT NULL DEFAULT 0,
    first_semantic_at_ms                INTEGER NOT NULL DEFAULT 0,
    done_at_ms                          INTEGER NOT NULL DEFAULT 0,
    request_bytes                       INTEGER NOT NULL DEFAULT 0 CHECK (request_bytes >= 0),
    response_bytes                      INTEGER NOT NULL DEFAULT 0 CHECK (response_bytes >= 0),
    estimated_input_tokens              INTEGER NOT NULL DEFAULT 0 CHECK (estimated_input_tokens >= 0),
    observed_input_tokens               INTEGER NOT NULL DEFAULT 0 CHECK (observed_input_tokens >= 0),
    observed_output_tokens              INTEGER NOT NULL DEFAULT 0 CHECK (observed_output_tokens >= 0),
    retry_after_until_ms                INTEGER NOT NULL DEFAULT 0,
    observation_order                   INTEGER NOT NULL CHECK (observation_order > 0),
    expected_cancel                     INTEGER NOT NULL DEFAULT 0 CHECK (expected_cancel IN (0,1)),
    observer_incomplete                 INTEGER NOT NULL DEFAULT 0 CHECK (observer_incomplete IN (0,1)),
    observer_incomplete_reason          TEXT NOT NULL DEFAULT '',
    reachability_disposition            TEXT NOT NULL CHECK (reachability_disposition IN
        ('not_applicable','applied','config_stale','superseded')),
    capability_disposition              TEXT NOT NULL CHECK (capability_disposition IN
        ('not_applicable','applied','config_stale','superseded')),
    calibration_run_id                  TEXT,
    candidate_ordinal                   INTEGER NOT NULL DEFAULT 0,
    created_at                          INTEGER NOT NULL,
    CHECK ((observer_incomplete=0 AND observer_incomplete_reason='') OR
           (observer_incomplete=1 AND observer_incomplete_reason IN
            ('observer_capacity','queue_full','input_limit','output_limit','decode_failure',
             'deadline','panic','prepare_failure'))),
    CHECK ((recipe_storage='db' AND recipe_version_id IS NOT NULL AND client_profile_id IS NULL AND template_id=''
            AND recipe_identity_revision=0) OR
           (recipe_storage='profile' AND recipe_version_id IS NULL AND client_profile_id IS NOT NULL AND template_id=''
            AND recipe_identity_revision>=1) OR
           (recipe_storage='embedded' AND recipe_version_id IS NULL AND client_profile_id IS NULL AND template_id!=''
            AND recipe_identity_revision>=1)),
    CHECK ((trigger='real_traffic' AND recipe_binding_use='real_traffic_context') OR
           (trigger!='real_traffic' AND recipe_binding_use!='real_traffic_context')),
    CHECK ((trigger!='real_traffic' AND real_request_shape_hash='' AND real_request_shape_learnable=0
            AND real_request_shape_unavailable_reason='') OR
           (trigger='real_traffic' AND
             ((real_request_shape_learnable=1 AND real_request_shape_hash!='' AND real_request_shape_unavailable_reason='') OR
              (real_request_shape_learnable=0 AND real_request_shape_hash='' AND
               real_request_shape_unavailable_reason IN
                ('body_truncated','unsafe_value','unsupported_shape','sanitizer_failure')))))
);
CREATE INDEX idx_probe_execution_sent_id ON probe_execution(sent_at_ms DESC, id DESC);
CREATE INDEX idx_probe_execution_upstream_sent ON probe_execution(upstream_id, sent_at_ms DESC, id DESC);
CREATE INDEX idx_probe_execution_route_sent ON probe_execution(route_id, sent_at_ms DESC, id DESC);
CREATE INDEX idx_probe_execution_endpoint_sent ON probe_execution(endpoint, sent_at_ms DESC, id DESC);
CREATE INDEX idx_probe_execution_error_sent ON probe_execution(error_class, sent_at_ms DESC, id DESC);
CREATE INDEX idx_probe_execution_trigger_sent ON probe_execution(trigger, sent_at_ms DESC, id DESC);

CREATE TABLE upstream_reachability (
    upstream_id                       INTEGER PRIMARY KEY REFERENCES upstream(id) ON DELETE RESTRICT,
    evidence_kind                     TEXT NOT NULL,
    endpoint                          TEXT NOT NULL,
    timeout_profile                   TEXT NOT NULL DEFAULT '',
    state                             TEXT NOT NULL CHECK (state IN ('unknown','reachable','unreachable')),
    consecutive_ok                    INTEGER NOT NULL DEFAULT 0,
    consecutive_fail                  INTEGER NOT NULL DEFAULT 0,
    last_ok_at                        INTEGER NOT NULL DEFAULT 0,
    last_error_at                     INTEGER NOT NULL DEFAULT 0,
    last_error                        TEXT NOT NULL DEFAULT '',
    last_connect_ms                   INTEGER NOT NULL DEFAULT 0,
    last_tls_ms                       INTEGER NOT NULL DEFAULT 0,
    last_header_ms                    INTEGER NOT NULL DEFAULT 0,
    observed_network_revision         INTEGER NOT NULL,
    settings_fingerprint              TEXT NOT NULL,
    observation_token                 TEXT NOT NULL,
    last_observation_order            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_reachability_state_upstream ON upstream_reachability(state, upstream_id);

CREATE TABLE endpoint_capability (
    id                                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_upstream_id                   INTEGER REFERENCES upstream(id) ON DELETE RESTRICT,
    scope_route_id                      INTEGER REFERENCES route(id) ON DELETE RESTRICT,
    endpoint                            TEXT NOT NULL CHECK (endpoint IN
        ('models','messages','responses','chat_completions','count_tokens')),
    endpoint_id                         INTEGER NOT NULL REFERENCES upstream_endpoint(id) ON DELETE RESTRICT,
    evidence_kind                       TEXT NOT NULL,
    timeout_profile                     TEXT NOT NULL DEFAULT '',
    state                               TEXT NOT NULL CHECK (state IN
        ('unknown','supported','unsupported','transient_error','config_error')),
    observation_token                   TEXT NOT NULL,
    resolved_url_hash                   TEXT NOT NULL DEFAULT '',
    upstream_network_revision           INTEGER NOT NULL,
    upstream_credential_revision        INTEGER NOT NULL,
    endpoint_revision                   INTEGER NOT NULL,
    model_capability_revision           INTEGER NOT NULL DEFAULT 0,
    route_capability_revision           INTEGER NOT NULL DEFAULT 0,
    auth_profile_revision               INTEGER NOT NULL,
    recipe_binding_revision             INTEGER NOT NULL,
    probe_settings_fingerprint           TEXT NOT NULL,
    probe_secret_revisions_hash          TEXT NOT NULL,
    request_transform_binding_revision   INTEGER NOT NULL DEFAULT 0,
    observed_at                         INTEGER NOT NULL DEFAULT 0,
    expires_at                          INTEGER NOT NULL DEFAULT 0,
    status_code                         INTEGER NOT NULL DEFAULT 0,
    error_class                         TEXT NOT NULL DEFAULT 'none',
    redacted_detail                     TEXT NOT NULL DEFAULT '',
    last_observation_order              INTEGER NOT NULL DEFAULT 0,
    last_real_ok_at                     INTEGER NOT NULL DEFAULT 0,
    last_real_ok_token                  TEXT NOT NULL DEFAULT '',
    CHECK ((scope_upstream_id IS NOT NULL) <> (scope_route_id IS NOT NULL))
);
CREATE UNIQUE INDEX idx_capability_upstream_endpoint
    ON endpoint_capability(scope_upstream_id, endpoint)
    WHERE scope_upstream_id IS NOT NULL;
CREATE UNIQUE INDEX idx_capability_route_endpoint
    ON endpoint_capability(scope_route_id, endpoint)
    WHERE scope_route_id IS NOT NULL;
CREATE INDEX idx_capability_state_observed
    ON endpoint_capability(state, observed_at DESC, id DESC);

CREATE TABLE calibration_run (
    id                       TEXT PRIMARY KEY,
    route_id                 INTEGER NOT NULL REFERENCES route(id) ON DELETE RESTRICT,
    endpoint                 TEXT NOT NULL CHECK (endpoint IN
        ('models','messages','responses','chat_completions','count_tokens')),
    state                    TEXT NOT NULL CHECK (state IN
        ('planned','running','succeeded','failed','canceled','interrupted')),
    current_ordinal          INTEGER NOT NULL DEFAULT 0,
    selected_ordinal         INTEGER,
    created_at               INTEGER NOT NULL,
    started_at               INTEGER NOT NULL DEFAULT 0,
    finished_at              INTEGER NOT NULL DEFAULT 0,
    revision                 INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1)
);
CREATE INDEX idx_calibration_route_created ON calibration_run(route_id, created_at DESC, id DESC);

CREATE TABLE calibration_candidate (
    run_id                       TEXT NOT NULL REFERENCES calibration_run(id) ON DELETE RESTRICT,
    ordinal                      INTEGER NOT NULL CHECK (ordinal >= 0),
    auth_mode                    TEXT NOT NULL,
    source_recipe_json           TEXT NOT NULL,
    materialized_recipe_json     TEXT NOT NULL DEFAULT '',
    state                        TEXT NOT NULL CHECK (state IN
        ('planned','prepared','send_started','finished','indeterminate')),
    execution_id                 TEXT REFERENCES probe_execution(id) ON DELETE RESTRICT,
    disposition                  TEXT NOT NULL DEFAULT '' CHECK (disposition IN
        ('','stop','try_next_auth','try_next_shape')),
    send_started_at              INTEGER NOT NULL DEFAULT 0,
    finished_at                  INTEGER NOT NULL DEFAULT 0,
    estimated_input_tokens       INTEGER NOT NULL DEFAULT 0 CHECK (estimated_input_tokens >= 0),
    PRIMARY KEY (run_id, ordinal)
);

CREATE TABLE probe_cost_daily (
    day_utc                   TEXT NOT NULL,
    trigger                   TEXT NOT NULL,
    origin                    TEXT NOT NULL,
    endpoint                  TEXT NOT NULL,
    route_id                  INTEGER NOT NULL DEFAULT 0,
    upstream_id               INTEGER NOT NULL DEFAULT 0,
    requests                  INTEGER NOT NULL DEFAULT 0 CHECK (requests >= 0),
    succeeded                 INTEGER NOT NULL DEFAULT 0 CHECK (succeeded >= 0),
    failed                    INTEGER NOT NULL DEFAULT 0 CHECK (failed >= 0),
    canceled                  INTEGER NOT NULL DEFAULT 0 CHECK (canceled >= 0),
    estimated_input_tokens    INTEGER NOT NULL DEFAULT 0 CHECK (estimated_input_tokens >= 0),
    observed_output_tokens    INTEGER NOT NULL DEFAULT 0 CHECK (observed_output_tokens >= 0),
    canceled_after_semantic   INTEGER NOT NULL DEFAULT 0 CHECK (canceled_after_semantic >= 0),
    piggyback_l2_saved        INTEGER NOT NULL DEFAULT 0 CHECK (piggyback_l2_saved >= 0),
    PRIMARY KEY (day_utc, trigger, origin, endpoint, route_id, upstream_id)
);
CREATE INDEX idx_probe_cost_page ON probe_cost_daily(
    day_utc DESC, trigger DESC, origin DESC, endpoint DESC, route_id DESC, upstream_id DESC);

CREATE TABLE probe_cost_event (
    event_id            TEXT PRIMARY KEY,
    day_utc             TEXT NOT NULL,
    event_kind          TEXT NOT NULL CHECK (event_kind IN ('execution','piggyback_l2')),
    evidence_version    INTEGER NOT NULL CHECK (evidence_version >= 1),
    cost_evidence_hash  TEXT NOT NULL
);
CREATE INDEX idx_probe_cost_event_day ON probe_cost_event(day_utc, event_id);

CREATE TABLE probe_cost_retention_watermark (
    singleton              INTEGER PRIMARY KEY CHECK (singleton=1),
    closed_through_day_utc TEXT NOT NULL DEFAULT ''
);
INSERT INTO probe_cost_retention_watermark(singleton, closed_through_day_utc) VALUES (1, '');

CREATE TABLE observation_sequence (
    singleton      INTEGER PRIMARY KEY CHECK (singleton=1),
    high_watermark INTEGER NOT NULL CHECK (high_watermark >= 0)
);
INSERT INTO observation_sequence(singleton, high_watermark) VALUES (1, 0);
