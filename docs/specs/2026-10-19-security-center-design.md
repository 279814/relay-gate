# Security Center 管理合同收口

依据 docs01 §14.5、§17、docs04 的 Probe 单一执行器和管理权限合同。独立分支从元数据 UI405 与 SMTP13 稳定检查点集成；schema14 Canary、15 原始留样、16 Transform 由各 owner 冻结，本 lane 等16稳定后才实现17迁移。旧 reader、备份和已冻结 DDL 形状保持其各自版本合同。

## 方案与边界

采用现有 SQLite finding、Sample、ProbeExecution 和 audit_event 作为各自单一权威，新增有限管理状态。纯前端过滤无法覆盖保留窗且计数失真；第二份原始证据库或诊断事件平台会重复正文、执行和恢复职责，均不采用。

1. Findings 使用服务端严格校验的 severity、Upstream ID、Route ID、rule_id、发现时间范围和 review/ignored 条件。按 `(at_ms DESC, id DESC)` keyset 翻页，游标包含资源和过滤指纹；count 与 page 在同一 SQLite 读事务中求值。时间依赖的 ignore 有效性固定在该轮分页的判定时刻。未知筛选字段/无效枚举/跨筛选游标返回400，持久读取失败显式失败，不回退另一内存列表。
2. 只在管理层标记 `open` / `false_positive`；按 finding 独立 revision CAS 更新并审计成功、冲突和失败。原 finding 的证据、严重级别、scanner/rule 版本不被重写，也不自动修改健康。
3. 忽略规则只有 `rule` 和 `route` 两种 scope，严格要求对应单一目标；包括正 revision、明确到期时间、enabled 和创建/更新时间。创建/更新/删除有界且 CAS；无任意脚本或自由理由正文。忽略不停止扫描、不删除 finding，仅抑制匹配的新告警并在查询中标明命中。后台 worker 直接读取同一 SQLite，无第二缓存、队列或转发等待；忽略策略读取失败不得伪造匹配。
4. 未脱敏证据只经服务端可信真实扫描身份、非空精确 ReqID、同 Route/Upstream 找到唯一已有 SampleAttempt。空、重复、过期、未采样、非原始响应视图、截断或不完整均诚实 unavailable，不以有限脱敏 Detail 冒充 raw、不按时间或当前 Route 猜关联。schema15 可证明原始视图后才允许原始响应入口；已有三份 Sample body 不在 finding 域复制。
5. 敏感读取沿用现有样本再次认证流程，额外要求有效 Cookie 会话；口令仅保留在当次请求和临时输入，不进存储。敏感 evidence 路径经现有 audit pending/首字节终结门禁：durable 结果失败时不返回明文字节。响应 `no-store`，所有证据通过 `x-text`，关闭/登出及新会话使迟到响应无效。
6. `security/diagnostics` 只关联 Canary14 的 `canary_execution` 与已有精确 ProbeExecution，不把旧普通 manual 执行推为 canary。运行入口继续复用 owner 的 `POST security/canary` → `probeAdmin` → Executor；只有用户显式一次性授权可在 Lazy 下执行，周期能力由14策略管理。本 lane 不另建诊断表/出站客户端，不发真实上游请求。手动禁用 Route 复用既有配置 CAS 和 route_disable 审计。

## 需要17持久字段

- `security_finding` 增加 `upstream_id`、`rule_id`：新真实采集携带已固定的身份；旧行默认0/空表示未知，不能用当前配置重构。内置规则使用固定 ID，自定义规则保留已有 `Rule.ID`；类别仍是类别。
- `security_finding_review(finding_id, status, revision, updated_at)`：只保存管理决定，关联 finding；未标记的逻辑默认是 open/revision1。
- `security_ignore_rule(id, scope, rule_id, route_id, expires_at, enabled, revision, created_at, updated_at)`：有限匹配元数据，不保存 Secret、原请求、自由错误或证据。
- 必要的固定分页/匹配索引及17精确 fingerprint、16→17配对 backup/reader、partial拒绝与恢复合同。DDL 需等16冻结后再固定，当前设计不先造迁移文件。

## 实施顺序与真实验证

先做无DDL的现有字段稳定 SQL 分页和 HTTP 参数合同；接着与14/15 owner固定诊断及证据 DTO。17落地后补 review/ignore CAS 与审计，再接前端过滤、分页、关联和再认证。每步先运行真实失败断言再最小实现，不以实现镜像测试代替行为。

SQLite 覆盖同时间多行、筛选计数、跨页稳定排序、坏游标、已取消context、损坏密文/Store失败、CAS并发与重启。HTTP 覆盖鉴权、未知字段、伪造ReqID无raw、唯一精确关联、无样本/截断/未知响应视图、Cookie再次认证、audit不可用零明文及 mutation失败如实审计。Node 覆盖筛选游标、旧会话结果、草稿冲突和纯文本；真实浏览器仅临时数据库与本地fixture，验证显示和精确导航，不触线上、私有输入或真实模型。
