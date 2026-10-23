# 最近错误中的 canonical 失败

`RequestLog.Outcome` 描述客户端转发结果。上游以 HTTP 200 返回结构化错误、空语义响应或缺少结束事件时，该值可以仍为 `ok`，不能据此排除已经持久化的 canonical 失败。

保留原 `outcome <> ok` 集合，并加入精确 `request_log_metadata.execution_id` 所指向的真实流量失败：Execution 已提交、`success=false`，且 ErrorClass 属于既有十种负类。`none`、`ignored`、`unknown` 不构成补充证据，不读取正文、不重新分类、不按 Route 或时间猜关联。执行详情超过保留期后，只使用同一观察事务已写入元数据的负类和实际提交 disposition；pending、unavailable、dropped 均不补充失败集合。

总数、游标页和细分类筛选复用同一个 SQL 条件，沿用单个只读事务。日志 Outcome、分类器、队列和 schema12 均不变。首页摘要在没有日志错误文本时展示已存 ErrorClass，列表继续同时展示 ErrorClass 与客户端 Outcome。

验证先用真实 HTTP、真实 SQLite 和既有异步 Recorder 重现 HTTP 200 JSON error、SSE 缺少结束事件及假活遗漏，再覆盖成功/预期取消、历史未知、观察提交延迟、无提交/队列丢弃和详情过期。API 验证细筛选及摘要字段，Node 合同验证客户端不会改写 `ok` 或退回相关 Route Execution。
