# 被动安全扫描执行设计

本次交付落实 `docs/01` §14.2–14.3 与 `docs/19` 的现有缺口，不改变健康、重试、响应正文、Flush 或自动禁用策略。

## 数据路径

安全采集包裹既有 `AttemptObserver`，仅复制原始上游响应字节及最小协议/请求工具上下文；原 RequestObserver、ResponseProgress、trace 与取消权威原样保留。健康观察器未安装时仍能独立采集。只有客户端已提交的响应进入扫描，丢弃尝试只释放资源。Transform 后正文不作为上游证据。

采集准入、队列及每条副本均有界；转发线程不解析、解压、扫描或等待证据数据库。首尾片段保留原始 offset 与缺口，后台在连续片段内使用重叠滚动窗口，禁止跨缺口拼接事件或模式。压缩正文无法在预算内恢复真实尾部时明确 incomplete，不无限解压。

后台复用中立 `protocol.Decoder` 的帧解析；新增默认关闭的 payload sink 只让安全工作线程临时访问完整事件对象，不把原文添加到脱敏健康事件。现有 probe 有界 gzip/br codec 移到中立包复用，probe 保持原公开调用形状。

## 规则与边界

规则结合协议位置、角色/工具、代码围栏、HTML 文档/登录/广告、凭据或私上下文请求、注入指令、可疑外链、隐藏 Unicode 与编码载荷。合法脚本单项仅为低等级线索，多信号或已知 Credential 泄漏才升级；不执行任何内容。请求工具列表未知时不假定工具未授权。

默认扫描最多 1 MiB 解码后正文、单个 SSE/NDJSON 事件 256 KiB。Base64、URL、Unicode 解码/规范化最多两层，派生累计字节 4 MiB；扫描执行预算 100 ms（可移植 monotonic 时间保守包含等待，另有确定性字节/工作预算）。规则只允许本地字符串、Unicode、结构条件或 Go RE2，正则模式最多 4 KiB。超限、坏编码、缺口、请求上下文缺失和预算耗尽均记录可解释 incomplete。每条 finding 带 scanner/rule version、bytes_scanned、truncated、decode_depth、incomplete_reason；证据限长并先按已知凭据脱敏。

旧 `ScanText` 与手动扫描委托同一引擎，不能绕过资源或元数据边界。每次扫描只保存有限证据；队满计 dropped 并由后台记录/告警，主链不等待持久化。

## 持久化与验收

先完成 Go 类型与真实测试；等待 RouteHealth schema9 稳定后，独占 schema10 添加 security_finding 的 truncated/decode_depth/evidence_hash 列（hash 仅覆盖有限脱敏证据，不是完整正文），并同步精确 reader、备份、恢复与迁移契约，不借旧列存 JSON。旧行明确默认未知/零层，不伪装升级后的扫描。

先红后绿覆盖合法代码、各类组合风险、三协议事件、gzip/br、尾部与跨 chunk 模式、跨缺口不误匹配、超限/坏编码/两层/CPU/RE2、队满/释放/持久 flush、原始字节与 Transform 隔离、健康 optional 接口透传和无观察器采集。所有测试使用临时数据库、合成凭据与 loopback；不访问私有输入或在线模型。
