-- Apply after legacy-m2.sql. This is the old startup crash point after
-- schema.sql created request_log but before migrate.go added sample.req_id.
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
