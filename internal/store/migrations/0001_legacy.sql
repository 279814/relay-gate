-- Schema version 1 baseline. This file is only executed for an empty database.
-- Connection and journal PRAGMAs are owned by the migration runner.
-- relay-gate schema。手写 SQL，不用 ORM（表就 7 张）。
--
-- 时间戳统一存 Unix 毫秒（INTEGER），不用 SQLite 的日期字符串：
-- 全链路要算 TTFT 这类毫秒级差值，存字符串每次都要解析，且时区是隐患。

-- journal_mode 是**库级持久**的：设一次就写进文件头，之后每条连接都是 WAL。

-- 下面两条是**连接级**的，写在这里只对执行本文件的那条连接生效。
-- 真正的生效点是 store.go 的 connPragmas（DSN 里带上，每条新连接都有）。
-- 这里保留是为了让手工 `sqlite3` 打开时行为一致，**不是**程序的依赖。

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

    -- 与 request_log 同组（M6），便于在「发了哪些字节」与「试过哪几个站」
    -- 之间互跳。空串 = 早于 M6 的样本，或请求日志被关掉了。
    --
    -- 列在这里是为了让新库一次建对、也让这张表的结构在本文件里是完整的；
    -- 但它的**索引不能放在本文件**，必须在 migrate.go 里建 —— 见那里的说明：
    -- 老库跑到这里时 CREATE TABLE 是空操作（列还不存在），紧接着的
    -- CREATE INDEX 就会因「no such column: req_id」直接让启动失败。
    req_id        TEXT    NOT NULL DEFAULT '',

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

-- 请求日志（M6）：**每次尝试一行**，靠 req_id 归组。
--
-- 为什么不复用 sample 表：
--   1. sample 只记**最终**那次尝试，而日志的全部价值在于「前两次为什么失败」
--   2. sample 可以关（sample_enabled），且队列满会丢、按 300 条滚动 ——
--      从一个会丢、会被截、可以关的数据源算成功率，得到的是一个**会骗人的
--      数字**。而这张表存在的理由就是回答「重试到底有没有用」
--   3. sample 存三份完整 body（现在还不封顶），日志只存元数据，
--      两者的保留策略必然不同
--
-- 这张表刻意**不存任何 body 与头**：那是 sample 的职责，重复存一份
-- 只会让磁盘翻倍，还多一处需要脱敏的地方（漏一处就是明文 key 落库）。
CREATE TABLE IF NOT EXISTS request_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,

    -- req_id 把同一次客户端请求的多次尝试串起来。
    -- 不用自增组号而用随机 id：组号要先查库再写，而写入在后台单 writer 里
    -- 排队，查一次库就多一次 I/O；随机 id 在转发路径上生成，零查询。
    req_id        TEXT    NOT NULL,
    -- attempt 从 1 开始；attempts 是这次客户端请求**总共**试了几次。
    --
    -- 两个字段有冗余（attempts 在同组内恒定），但列表页要显示「3 次尝试」
    -- 而不必先把整组拉出来数 —— 而那正是列表页最常见的查询。
    attempt       INTEGER NOT NULL DEFAULT 1,
    attempts      INTEGER NOT NULL DEFAULT 1,

    ts_recv       INTEGER NOT NULL,
    ts_sent       INTEGER NOT NULL DEFAULT 0,
    ts_first_byte INTEGER NOT NULL DEFAULT 0,
    ts_done       INTEGER NOT NULL DEFAULT 0,

    endpoint      TEXT    NOT NULL DEFAULT '',
    model_in      TEXT    NOT NULL DEFAULT '',
    model_out     TEXT    NOT NULL DEFAULT '',
    model_name_id INTEGER NOT NULL DEFAULT 0,
    route_id      INTEGER NOT NULL DEFAULT 0,
    upstream_id   INTEGER NOT NULL DEFAULT 0,
    -- 上游名字冗余存一份：Upstream 被删掉之后，日志仍要能说清
    -- 「当时走的是哪个站」。存 id 关联查的话，删站等于把历史抹平。
    upstream_name TEXT    NOT NULL DEFAULT '',

    resp_status   INTEGER NOT NULL DEFAULT 0,
    ttft_ms       INTEGER NOT NULL DEFAULT 0,
    bytes_written INTEGER NOT NULL DEFAULT 0,

    outcome       TEXT    NOT NULL DEFAULT '',
    -- retried 表示这次尝试**被丢弃并换了站**。它不等于 outcome != 'ok'：
    -- 最后一次尝试失败时也是失败，但没有被重试（次数用尽或不可重试）。
    -- 区分这两者才能回答「重试有没有救回来」。
    retried       INTEGER NOT NULL DEFAULT 0,
    -- 半开放行的尝试（§4.4c）。它的失败预期就高，混进成功率会拉低整体数字
    -- 并让人误以为站的质量在下降。
    half_open     INTEGER NOT NULL DEFAULT 0,
    error         TEXT    NOT NULL DEFAULT ''
    -- 与样本的关联挂在 **sample.req_id** 上，不在这里存 sample_id：
    -- 样本 id 由后台 writer 落库时才分配，而日志在转发路径上就要写出去 ——
    -- 那一刻 sample_id 还不存在。req_id 是请求开始时我们自己生成的，
    -- 两边都同步可知。加列见 migrate.go。
);

-- 列表页按时间倒序翻页；详情页按 req_id 取整组。
CREATE INDEX IF NOT EXISTS idx_reqlog_ts       ON request_log (ts_recv DESC);
CREATE INDEX IF NOT EXISTS idx_reqlog_req      ON request_log (req_id, attempt);
CREATE INDEX IF NOT EXISTS idx_reqlog_route    ON request_log (route_id, ts_recv DESC);
CREATE INDEX IF NOT EXISTS idx_reqlog_upstream ON request_log (upstream_id, ts_recv DESC);

CREATE INDEX IF NOT EXISTS idx_sample_req ON sample (req_id);

CREATE TABLE schema_version (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version   INTEGER NOT NULL
);

