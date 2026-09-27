-- schema 7: Sample Group (docs/01 §5.4 / §5.7).
-- 一个客户端请求 = 一条 sample_request（入站请求只存一次）+ 每次实际发给
-- 上游的 sample_attempt。旧 sample 每行迁成一条 request 和一条代表旧最终
-- 尝试的 attempt；历史中未保存的重试 body 不伪造。BLOB 原样复制，
-- 明文与信封形态都保持不变（双读仍然成立）。

CREATE TABLE sample_request (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    legacy_sample_id INTEGER UNIQUE,
    req_id           TEXT    NOT NULL DEFAULT '',
    ts_recv          INTEGER NOT NULL,
    endpoint         TEXT    NOT NULL DEFAULT '',
    model_in         TEXT    NOT NULL DEFAULT '',
    in_method        TEXT    NOT NULL DEFAULT '',
    in_path          TEXT    NOT NULL DEFAULT '',
    in_query         TEXT    NOT NULL DEFAULT '',
    in_headers       TEXT    NOT NULL DEFAULT '{}',
    in_body          BLOB,
    truncated        INTEGER NOT NULL DEFAULT 0,
    pinned           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_sample_request_ts     ON sample_request (ts_recv DESC);
CREATE INDEX idx_sample_request_pinned ON sample_request (pinned, id DESC);
CREATE INDEX idx_sample_request_req    ON sample_request (req_id);

CREATE TABLE sample_attempt (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id    INTEGER NOT NULL REFERENCES sample_request(id) ON DELETE CASCADE,
    ts_recv       INTEGER NOT NULL DEFAULT 0,
    ts_sent       INTEGER NOT NULL DEFAULT 0,
    ts_first_byte INTEGER NOT NULL DEFAULT 0,
    ts_done       INTEGER NOT NULL DEFAULT 0,
    model_out     TEXT    NOT NULL DEFAULT '',
    model_name_id INTEGER NOT NULL DEFAULT 0,
    route_id      INTEGER NOT NULL DEFAULT 0,
    upstream_id   INTEGER NOT NULL DEFAULT 0,
    out_url       TEXT    NOT NULL DEFAULT '',
    out_headers   TEXT    NOT NULL DEFAULT '{}',
    out_body      BLOB,
    resp_status   INTEGER NOT NULL DEFAULT 0,
    resp_headers  TEXT    NOT NULL DEFAULT '{}',
    resp_body     BLOB,
    outcome       TEXT    NOT NULL DEFAULT '',
    error         TEXT    NOT NULL DEFAULT '',
    truncated     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_sample_attempt_request ON sample_attempt (request_id, id);
CREATE INDEX idx_sample_attempt_route   ON sample_attempt (route_id);

-- truncated 位：1 = in_body（归 request），2 = out_body、4 = resp_body（归 attempt）。
INSERT INTO sample_request (id, legacy_sample_id, req_id, ts_recv, endpoint, model_in,
    in_method, in_path, in_query, in_headers, in_body, truncated, pinned)
SELECT id, id, req_id, ts_recv, endpoint, model_in,
    in_method, in_path, in_query, in_headers, in_body, truncated & 1, pinned
FROM sample ORDER BY id;

INSERT INTO sample_attempt (request_id, ts_recv, ts_sent, ts_first_byte, ts_done,
    model_out, model_name_id, route_id, upstream_id,
    out_url, out_headers, out_body, resp_status, resp_headers, resp_body,
    outcome, error, truncated)
SELECT id, ts_recv, ts_sent, ts_first_byte, ts_done,
    model_out, model_name_id, route_id, upstream_id,
    out_url, out_headers, out_body, resp_status, resp_headers, resp_body,
    outcome, error, truncated & 6
FROM sample ORDER BY id;

DROP TABLE sample;
