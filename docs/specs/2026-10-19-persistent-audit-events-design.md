# 管理操作的持久审计

依据 docs/01 §5.4、§5.5、§12–13：敏感查看、凭据轮换、失败与回滚、Recipe 与 ClientProfile 发布和强制启用、Route 手动停用等管理行为进入同一 SQLite audit_event。它是唯一历史权威；删除 credential.Service 的 200 条内存审计缓存。审计不参与真实转发，不增加业务请求队列或通用事件平台。

schema 11 只增加 audit_event 与四个查询索引。记录自增 id、随机 operation_id、起止毫秒时间、类别、受限动作码、资源类型与有限标识、不可逆 actor_hash、pending/succeeded/failed/unknown 结果和固定 reason_code。不存自由 detail、原始错误、请求 body、密码、Key、Cookie、IP 或业务证据。资源标识由服务器规范化，actor 仅用经过验证的会话高熵 Token 的域隔离摘要；Bearer 管理来源只保留固定来源摘要。

管理路径先持久记录 pending，再执行敏感动作；无法记录就不执行，也不泄露敏感值。敏感查看必须在成功审计落盘后才返回明文。变更失败记录固定错误类别；变更已完成后终结审计失败不能伪报变更失败、诱导重复轮换，而是保留 pending，返回已完成结果及 audit_pending 标识。启动前把上次进程未终结的 pending 标为 unknown，明确无法证明完成结果，不能猜测成功或回滚。文件/Keyring 与 SQLite 不能假称同一事务；审计开始、终结均为短事务，既有领域事务继续作为变更成功的权威。

统一 GET /admin/api/audit-events 沿用管理员鉴权和 no-store；按 id 降序 keyset 分页，首屏冻结最大 id，翻页绑定筛选指纹，单页 1–200 条。支持 category/action/outcome、时间范围和资源类型/id；不提供无界加载。凭据页读取此持久历史，提供筛选和下一页，始终以纯文本渲染。

10→11 在首笔 DDL 前创建配对 schema 10 备份，准确记录运行程序 SHA-256、schema-10-security-scan-v1-reader 和源 fingerprint。schema 11 备份使用独立 schema-11-audit-v1-reader。严格检查完整表、索引和基础 schema 10；部分迁移、额外对象或修改定义拒绝启动。保留 schema 7/8/9/10 历史 reader 和只读验证。

先完成并冻结 schema 11/Store 分页 checkpoint，再逐类接管理事件。使用真实 SQLite 和 HTTP 验证迁移备份失败、半迁移拒绝、重启、分页插入/筛选、敏感查看审计失败不泄密，以及变更成功后日志失败不会重复执行。仅凭据接线完成时不宣称 §5.5 全事件完成。
