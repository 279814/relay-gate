-- relay-gate schema。手写 SQL，不用 ORM（表就 6 张）。
--
-- 时间戳统一存 Unix 毫秒（INTEGER），不用 SQLite 的日期字符串：
-- 全链路要算 TTFT 这类毫秒级差值，存字符串每次都要解析，且时区是隐患。

PRAGMA journal_mode = WAL;      -- 探活与样本写入并发，WAL 避免读写互锁
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS upstream (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE,
    base_url      TEXT    NOT NULL,
    -- AES-GCM 密文（base64）。明文 key 绝不落库，读出时才解密。
    api_key_enc   TEXT    NOT NULL,
    auth_style    TEXT    NOT NULL DEFAULT 'auto',
    full_url_mode INTEGER NOT NULL DEFAULT 0,
    proxy_url     TEXT    NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    l1_path       TEXT    NOT NULL DEFAULT '/v1/models',
    -- 探活头覆盖，JSON 对象；空串表示用全局模板
    probe_headers TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS model_name (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL UNIQUE,
    protocol         TEXT    NOT NULL,
    match_mode       TEXT    NOT NULL DEFAULT 'exact',
    is_fallback      INTEGER NOT NULL DEFAULT 0,
    probe_prompt     TEXT    NOT NULL DEFAULT '1+1=?',
    probe_max_tokens INTEGER NOT NULL DEFAULT 1,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
);

-- 每种协议至多一个兜底 ModelName。用部分唯一索引在**存储层**保证，
-- 而不是靠应用层先查后写——后者在并发下会漏。
--
-- 粒度是「每协议」而不是「全局」：兜底要转发到具体端点，而端点与协议
-- 一一对应（§3.1）。全局只allow一个的话，另外两个端点永远拿不到兜底 ——
-- 那两个端点上任何未配置的模型都会收到一个「协议不一致」的 400，
-- 而用户的意图明明是「都走兜底」。
DROP INDEX IF EXISTS idx_model_name_single_fallback;
CREATE UNIQUE INDEX IF NOT EXISTS idx_model_name_fallback_per_protocol
    ON model_name (protocol) WHERE is_fallback = 1;

CREATE TABLE IF NOT EXISTS route (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name_id   INTEGER NOT NULL REFERENCES model_name(id) ON DELETE CASCADE,
    upstream_id     INTEGER NOT NULL REFERENCES upstream(id)   ON DELETE CASCADE,
    priority        INTEGER NOT NULL DEFAULT 1,
    weight          INTEGER NOT NULL DEFAULT 100,
    -- 空串 = 不映射，body 一个字节都不改（§3.3.2 推荐路径）
    upstream_model  TEXT    NOT NULL DEFAULT '',
    max_concurrency INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    -- 同一组合只能绑一次，否则选路时同一个站会被重复计入权重
    UNIQUE (model_name_id, upstream_id)
);

CREATE INDEX IF NOT EXISTS idx_route_model_name ON route (model_name_id);
CREATE INDEX IF NOT EXISTS idx_route_upstream   ON route (upstream_id);

-- 健康状态以内存为准，这张表只是重启前的快照，用于 UI 展示历史。
-- 重启后所有 Route 一律按 unknown 处理（§2.4），不从这里恢复 state。
CREATE TABLE IF NOT EXISTS route_health (
    route_id         INTEGER PRIMARY KEY REFERENCES route(id) ON DELETE CASCADE,
    state            TEXT    NOT NULL DEFAULT 'unknown',
    consecutive_ok   INTEGER NOT NULL DEFAULT 0,
    consecutive_fail INTEGER NOT NULL DEFAULT 0,
    last_ok_at       INTEGER NOT NULL DEFAULT 0,
    last_err_at      INTEGER NOT NULL DEFAULT 0,
    last_error       TEXT    NOT NULL DEFAULT '',
    last_ttft_ms     INTEGER NOT NULL DEFAULT 0,
    updated_at       INTEGER NOT NULL
);

-- 单行表：全局设置（JSON）与服务运行状态。
-- 用 key-value 而不是宽表，是因为 Settings 会随功能增删字段，
-- 每加一个配置项就改一次 schema 不划算。
CREATE TABLE IF NOT EXISTS setting (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 请求/响应样本（§3.6）。
-- body 用 BLOB 存**原始字节**，不是重新序列化的 JSON——
-- 整个功能的意义就在于「发出去的到底是哪些字节」，转一道就失去了价值。
CREATE TABLE IF NOT EXISTS sample (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,

    ts_recv       INTEGER NOT NULL,           -- 收到入站请求
    ts_sent       INTEGER NOT NULL DEFAULT 0, -- 向上游发出
    ts_first_byte INTEGER NOT NULL DEFAULT 0, -- 上游首字节（用于算 TTFT）
    ts_done       INTEGER NOT NULL DEFAULT 0,

    endpoint      TEXT    NOT NULL,
    model_in      TEXT    NOT NULL DEFAULT '',
    model_out     TEXT    NOT NULL DEFAULT '',
    model_name_id INTEGER NOT NULL DEFAULT 0,
    route_id      INTEGER NOT NULL DEFAULT 0,
    upstream_id   INTEGER NOT NULL DEFAULT 0,

    in_method     TEXT    NOT NULL DEFAULT '',
    in_path       TEXT    NOT NULL DEFAULT '',
    in_query      TEXT    NOT NULL DEFAULT '',   -- ?beta=true 在这里，丢了会改变上游行为
    in_headers    TEXT    NOT NULL DEFAULT '{}', -- JSON，key 已脱敏
    in_body       BLOB,

    out_url       TEXT    NOT NULL DEFAULT '',
    out_headers   TEXT    NOT NULL DEFAULT '{}',
    out_body      BLOB,

    resp_status   INTEGER NOT NULL DEFAULT 0,
    resp_headers  TEXT    NOT NULL DEFAULT '{}',
    resp_body     BLOB,

    outcome       TEXT    NOT NULL DEFAULT '',
    error         TEXT    NOT NULL DEFAULT '',
    truncated     INTEGER NOT NULL DEFAULT 0,   -- 位标记：哪些字段被截断
    pinned        INTEGER NOT NULL DEFAULT 0    -- 置顶，不参与滚动清理
);

-- 清理按 id 倒序取前 N 条、按 ts_recv 删过期，两个索引都要。
-- pinned 进索引是因为清理语句每次都带 pinned = 0 条件。
CREATE INDEX IF NOT EXISTS idx_sample_ts     ON sample (ts_recv DESC);
CREATE INDEX IF NOT EXISTS idx_sample_pinned ON sample (pinned, id DESC);
CREATE INDEX IF NOT EXISTS idx_sample_route  ON sample (route_id, ts_recv DESC);
