# 逐 Attempt 事实与精确关联

原合同为 docs/01 §13.2、§16.1–§16.3。实现仅记录实际发送的 Attempt，沿现有 Canonical Trace、Decoder、Observer 读取时间和写入事实，不另造分类器。用户已授权按原合同持续完成。

采用固定列的 request_log_metadata、sample_attempt_metadata 附属表，分别以现有行 ID 为级联外键。这样旧 schema 7–11 的已审核物理结构保持原样；历史行没有附属记录时显式 unknown，绝不用当前配置回填。直接扩展旧表需要逆向重建旧 DDL，单一全局元数据表需要另做孤儿清理，两者均增加恢复复杂度。

schema 12 先生成 schema 11 配对备份，再在同一事务创建完整附属表与索引，最后提升版本。识别器精确校验新对象并交回旧 schema 11 验证器；部分结构、变化列、未知索引一律拒绝。7–11 的 reader/backup 合同保留，12 增加独立 reader 合同。

出站准备时冻结根配置代、Settings 行修订、ResolvedTarget Endpoint/AuthProfile 修订、Route/Model/Upstream 修订、Transform 版本；每次实际发送生成唯一 correlation 并传入 Observer。日志和样本携带相同 Execution ID。Capability effect 取该 ID 对应的已提交 ProbeExecution disposition；提交前标 pending，无 Observer 标 unavailable，旧记录标 unknown。查询精确配对自然支持日志先与观察先，不增加缓存、队列或时间相邻猜测。

元数据只含有界 typed 值。样本哈希仅来自无 Secret 污点的完整请求体；已知凭据命中、SecretRef 污点或不完整时省略并给固定原因。差异只保存 body/header 是否改变的结构化事实，不保存业务片段。样本关闭不会增加正文副本。synthetic completion 来自实际写出的 Transform 结果。

验证先覆盖真实 SQLite 迁移、备份/恢复、未知结构拒绝，再覆盖真实 HTTP 重试与配置快照、阶段时间和精确 Observation 关联、坏密文下元数据读取、最近错误细类别筛选。UI 使用 Node 合同和必要浏览器验证；组合分支的 Linux race CI 由根任务统一执行。

## 已实现的读取和收尾边界

`GET /samples/{id}/metadata` 只读取请求身份、每次尝试的基本事实与 typed 元数据，不 SELECT 头、URL、错误正文或密文 body；管理鉴权仍然生效。它在三份正文和所有头损坏时仍可读取。查看正文继续使用已有重认证流程。count_tokens 每次实际 RoundTrip 写轻量日志，本地跳过不产生 Attempt，沿用既有不保存 count_tokens 样本的规则。

完整非流式响应转换可记录安全的前后 hash 与 body/header 是否改变；SecretRef 或已知凭据命中时省略整个 hash/diff，使用固定 `secret_taint` 原因。未完整读取的流式响应使用 `incomplete`，样本关闭使用 `sample_disabled`。SSE synthetic 标记来自实际写出后的结果，不能由配置中存在一条规则反推。响应 fail_closed 发生在实际发送后时，仍保存该 Attempt 的日志和样本组。

`response_view` 从已保存事实派生，不增加 DDL：旧行为未知为 `unknown`；未采样为 `not_sampled`；丢弃尝试为 `upstream_attempt_prefix`；最终尝试为 `client_response`。后者表达采集位置，不能称为原始上游 wire。

## 仍需独立补齐的原始响应样本合同

原 docs/01 §5.4 第 445–450 行规定 sample_attempt 保存响应并保留“所有上游响应”；§16.3 第 1858–1867 行要求每次上游响应与变换前后事实。docs/04 第 2637 行进一步说明需要诊断的原始字节由 Sample 旁路按其权限保存。现有最终 RespTee 在客户端写入后采集，响应 Transform 因而会让样本 body/header/status 成为客户端视图；丢弃尝试只保存 peek 与最多 4 KiB 的复用 drain。它们都不足以声称可重放完整原始上游响应。401 的原始 Capture 仅供扫描，不能充当样本证据。此检查点保留既有正文行为并明确标记视图，后续应移动现有采集点到 Transform 前，复用现有 spill、配额与异步 writer，不新增第三份响应正文或为留档无限 drain。
