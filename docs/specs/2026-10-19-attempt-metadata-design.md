# 逐 Attempt 事实与精确关联

原合同为 docs/01 §13.2、§16.1–§16.3。实现仅记录实际发送的 Attempt，沿现有 Canonical Trace、Decoder、Observer 读取时间和写入事实，不另造分类器。用户已授权按原合同持续完成。

采用固定列的 request_log_metadata、sample_attempt_metadata 附属表，分别以现有行 ID 为级联外键。这样旧 schema 7–11 的已审核物理结构保持原样；历史行没有附属记录时显式 unknown，绝不用当前配置回填。直接扩展旧表需要逆向重建旧 DDL，单一全局元数据表需要另做孤儿清理，两者均增加恢复复杂度。

schema 12 先生成 schema 11 配对备份，再在同一事务创建完整附属表与索引，最后提升版本。识别器精确校验新对象并交回旧 schema 11 验证器；部分结构、变化列、未知索引一律拒绝。7–11 的 reader/backup 合同保留，12 增加独立 reader 合同。

出站准备时冻结根配置代、Settings 行修订、ResolvedTarget Endpoint/AuthProfile 修订、Route/Model/Upstream 修订、Transform 版本；每次实际发送生成唯一 correlation 并传入 Observer。日志和样本携带相同 Execution ID。Capability effect 取该 ID 对应的已提交 ProbeExecution disposition；提交前标 pending，无 Observer 标 unavailable，旧记录标 unknown。查询精确配对自然支持日志先与观察先，不增加缓存、队列或时间相邻猜测。

元数据只含有界 typed 值。样本哈希仅来自无 Secret 污点的完整请求体；已知凭据命中、SecretRef 污点或不完整时省略并给固定原因。差异只保存 body/header 是否改变的结构化事实，不保存业务片段。样本关闭不会增加正文副本。synthetic completion 来自实际写出的 Transform 结果。

验证先覆盖真实 SQLite 迁移、备份/恢复、未知结构拒绝，再覆盖真实 HTTP 重试与配置快照、阶段时间和精确 Observation 关联、坏密文下元数据读取、最近错误细类别筛选。UI 使用 Node 合同和必要浏览器验证；组合分支的 Linux race CI 由根任务统一执行。
