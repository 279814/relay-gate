# 原始上游响应样本

原合同：docs/01 §5.4 保存每次上游响应，§16.3 保存变换前后事实；docs/04 第 2637 行把需要诊断的原始字节交给 Sample。原最终 RespTee 位于客户端写出后，响应 Transform 因而改写了样本正文、头和状态。父任务已授权修正此缺口，保留三份正文定义，不增加第三份响应副本。

## 最小持久区分

schema 12 的 metadata_version CHECK 固定为 1，不能无迁移升到 2；也不能从当前程序版本推断历史样本视图。按父任务自检建议，预留 schema 15，仅向 sample_attempt_metadata 追加 response_capture_view 固定 enum，默认 legacy，新值为 upstream_response、upstream_attempt_prefix、no_response。旧 Version 1 的 legacy 行永远按其原 Retried 事实显示 client_response/prefix；没有元数据的旧行仍 unknown。新原始样本在既有 sample 事务中显式写枚举。RequestLog 继续表达客户端状态和写入字节。

迁移等待 Canary schema 14 稳定检查点，先生成 14 的配对备份，再执行确切 ALTER，最后提升版本。15 校验器只剥这一个精确追加列，恢复原 12 表声明后交给 14/13 既有物理指纹链。旧 12–14 DDL、reader 合同不变；部分列、未知索引和修改声明一律拒绝。

## 采集位置

复用现有唯一 sample.HeadTail、spill、磁盘配额及异步 writer。普通透传保留写入和 Flush 后复制原缓冲的顺序。启用响应 Transform 的路径把同一个 Sample sink 接到原始 upstream reader，位于解压、改写和 synthetic 输出之前。现有客户端 shadow 仍只读取客户端写出视图；401 独立扫描 Observer 和共享 Decoder 不变。peek 与 drain 只采一次，不能和 replay 的 prefix 重复计入。

在 Send 返回时为启用的样本冻结上游 status/header；后续样本用它们，RequestLog 保留最终客户端 status/bytes。记录真实 EOF。没有消费到 EOF 的丢弃/取消/中断响应设置 TruncRespBody，保留现有 4 KiB drain 上限；不为样本额外读完整上游流。无 HTTP 响应的实际 Attempt 使用 no_response。

## 隐私、验证与风险

样本关闭时不增加正文采集或快照。认证头、URL、正文继续使用已知凭据脱敏；SecretRef 和已知凭据污染的 hash/diff 省略。压缩响应仍保存原始编码字节，不能为了诊断改写客户端 wire；压缩/不完整样本的凭据检测能力必须实证，不能把编码后的污点当作安全内容。

先用真实 HTTP 的 response status/header/body 改写、gzip/br SSE、synthetic、fail_closed、重试 discard、partial/取消及 spill/配额测试复现旧问题，再移动唯一采集点。存储验证覆盖 legacy 与 raw view 混存、坏 cipherbody metadata 读取、15 迁移备份恢复和严格指纹。最后检查普通 Flush 顺序、扫描 Observer 和请求日志语义未受影响。
