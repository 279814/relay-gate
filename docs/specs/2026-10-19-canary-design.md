# Canary 严格诊断与 schema 14

本轮依据 docs/01 §14.4、§16.2 与 docs/04，基于冻结组合 `36717eb`。统计 PR407 已独立冻结。沿用 Executor → 统一协议 Decoder → ResultRecorder → Store 事务，以及现有 Scheduler / admission；不另建 HTTP、framer、健康归约或记账权威。

## 选择与行为

直接给旧 Trigger/Recipe 主表扩充枚举需要重建关联表，也会把诊断伪装成普通 Recipe。本轮选择有限 side facts：普通 ProbeExecution 仍保存唯一网络观测，Canary source、期望和严格结论以 execution_id 关联；成本经原幂等 gate 写到单独 daily 账本。只在内存标识 Canary 则无法解释保留后的历史来源，故不采用。

每次生成 128-bit 随机 nonce，最小上下文只要求调用一次 `relay_canary_noop`，参数严格为本次 nonce；该工具永远不执行，不读取项目、历史请求、用户工具或真实会话。统一 Decoder 的临时 PayloadSink 检查协议对象，严格拒绝额外文本、其他工具、重复调用、错误 nonce/额外参数、拒绝和不完整输出。等待协议正常结束后才判 passed，不能在首语义时误把后续违例漏掉；总量、事件、时间仍受 Executor 预算限制。nonce 只在本次内存请求/校验中存在，落库仅保存 SHA-256 和版本化期待事实。

Canary verdict 与普通 Probe Decision 独立。该诊断不附健康写入 expectation，因此失败不会自动改变模型、Route 或上游健康。现有普通手动 Probe 行为不变。

## 冻结 DDL 范围

仅新增 `0014_canary.sql`，不改任何历史 migration：

- `canary_policy`：upstream_id 主键/FK CASCADE，route_id FK CASCADE；enabled 默认 0，interval_sec 默认 3600（300–86400），revision >= 1。没有行等同周期关闭。Store 验证 Route 属于该 Upstream，只有 Active 才可启用；切 Lazy 后调度再次检查，不能产生周期请求。
- `canary_execution`：execution_id 主键/FK probe_execution CASCADE；source=manual|periodic；policy_revision（manual=0、periodic>=1）；expectation_version=1；nonce_sha256；expected_tool=relay_canary_noop；verdict=passed|violation|incomplete|canceled|execution_failed|not_sent；nullable nonce_matched/tool_matched 区分未知；input_usage_present/output_usage_present；evidence_hash 绑定不可变诊断事实。无正文和 nonce 原文。
- `canary_cost_daily`：主键为 day_utc/source/endpoint/route_id/upstream_id；executions、requests、passed、violated、incomplete、canceled、execution_failed、not_sent、estimated_input_tokens、observed_output_tokens、unknown_input_rows、unknown_output_rows 均非负。来源不会归因到某个普通 Recipe。使用现有 730 日关闭水位，不新增 retention 权威。
- `probe_cost_event.canary_source`：追加非空列，默认空串，枚举空串/manual/periodic。旧事件的 hash/version 合同不变；Canary 经原事件幂等 gate 绑定 source 和事实 hash，事务内选择 Canary daily。重复记录不重复计数，内容冲突拒绝。

schema 14 严格 inspector 移除精确的三张表/索引和追加列后必须得到已知 schema 13；部分结构、改约束、额外索引、伪版本均拒绝。迁移先锁内验证与加密检查，创建配对 schema-13 backup 后才改 DDL，版本行为最后写。schema-14-canary-v1 / schema-14-canary-v1-reader 用于当前 rotation backup 和 restore；7–13 历史合同保留。

## 服务与界面

`POST /admin/api/security/canary` 使用真实 `Service.RunCanary(ctx, routeID)`，明确手动一次性调用允许 Lazy，未装配则失败而非 record_only 假成功。周期策略使用管理员 typed CAS API，默认关闭；Scheduler 原 tick 仅为 Active、启用且仍匹配的目标安排一次 Canary，服从暂停/关闭、合成额度和去重。手动及周期都走同一 Executor 和 Recorder。

结果页按真实 execution_id 读取 typed 期待/结论/来源，纯文本显示，不把旧 manual 推为 Canary。独立 daily 只显示保留范围内已记录成本，usage 缺失或零但未知 presence 时保持 unknown。所有接口复用管理员权限、审计、no-store、有界筛选和 keyset，界面不拉全历史。Security Center lane 可按 canary_execution.execution_id 复用结果，不另造诊断表。

## 交付顺序与验证

先冻结完整 14 DDL/inspect/reader/backup/restore 检查点供后续 15/16/17 编译；此检查点只证明迁移，不宣称 Canary 行为完成。真实合成 SQLite 红绿覆盖 13→14 凭据/历史不变、backup 先于 DDL、backup 失败不写、当前 reader restore、部分/改约束/额外结构拒绝。随后严格输出矩阵覆盖三协议、分片和工具索引、nonce 复用/错误/额外输出、取消/超限/incomplete，真实 loopback 验证恰好一次、Lazy manual、Active 周期、暂停/切 Lazy、费用幂等/保留。最后 HTTP/Node/必要浏览器、相关全包、build/vet 和 committed history 检查。只使用合成 fixture 与 loopback，不调用线上模型、不读 .local、不更改时长或候选 soak 证据。

迁移检查点已实测：原 schema13→期望14 失败后变绿；SQLite 的 TEXT PRIMARY KEY 允许 NULL 导致未关联执行的回归再次真实失败，补显式 NOT NULL 后变绿。Canary 迁移/约束/严格 catalog/rotation restore 五个测试入口（含多个变体）通过；历史 schema/reader/SMTP/metadata 门禁、build/vet 与真实 binary runtime 验证通过。历史13的 rotation 测试固定使用13 fixture，仍精确断言原 reader 合同。

