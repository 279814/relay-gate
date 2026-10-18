# P0-16 在线对照工具收口

本设计落实 docs/04 的 P0-16 与 docs/01 §8.14、§20.1、§23；不改变目标，不执行用户私有输入或真实计费请求。基线为 bcaec875。

## 执行链

每次已授权 CLI 调用使用独立、仅当前用户可访问的临时目录和现有 Store schema。ConfigAdmin 创建显式五 Endpoint、模型及 Route，Source 发布同代快照，Sequencer 分配顺序。生产 RecipeResolver、outbound Provider/Resolver、TransportManager、Executor、Decoder/Classifier 与 ResultRecorder 完成请求准备、单次发送和结果记录。Scheduler 仅提供 PrepareManual，不启动调度循环。运行结束关闭连接、Store 并清理本次临时目录。

选择此方案而非 CLI 内存假来源或另一套 HTTP 分类：它复用严格准备与事务不变量，无 schema、新缓存或长驻服务。CLI 仅装配和输出脱敏 DTO，不实现 URL、Auth、流解析、重试或阶段计时。

每站 models 一次；每个声明模型的端点 Probe 一次，无隐藏重试。有对应 control 时另执行一次已验证原始 control，然后执行一次 Probe；两次均经过同一 Executor，报告两份实际结论和时间差。缺 control 仅为 control_missing，不能声称原生一致；control 成功而 Probe 失败为非零。

## Control 输入

版本 1 manifest 显式引用 typed v2 fixture；headers 哈希覆盖 fixture 内原始有序 header 数组的 JSON 字节，body 哈希覆盖解码后的原始 body bytes。旧 capture v1 不具备相同来源/隔离合同，不自动升级为可信 control。严格校验协议/端点、一次性 control ID/nonce、专用隔离会话来源及配置/MCP/hook/plugin/环境隔离证据、完整捕获、认证占位符、原始 header/body SHA-256 和长度。只接受固定无隐私 control 提示；附件、工具结果、真实凭据或不明正文拒绝，不从“最近样本”或历史任务恢复。

读取前验证 realpath、允许根、Git/Docker 排除、全部祖先无 symlink/reparse、regular file 和用户专属权限；文件句柄读取前后身份一致、内容有界。每一次发送前复查 freshness：completed_at 不在未来，captured_at≤completed_at，control 完成至 Probe 开始不超过 60 秒。任何输入错误在首次联网和输出文件创建前拒绝。

Control 在临时 Store 物化为不可变 draft version，经现有 Service.Test 使用显式绑定执行；只替换目标 URL/Host/Auth 和必要的唯一 model（复用生产字节替换函数），不重编码原始 body。认证占位符转换成显式 Endpoint AuthProfile，真实值只由生产 Auth 层填写。HTTP 库管理的 Host/Content-Length/逐跳字段按生产保护层处理；header 数组保留名称顺序和每项多值作为捕获证据，不声称 net/http 保证 wire 上的跨名称排序。

## 授权、隐私与脚本

缺 --online 或 --accept-probe-cost，或提供 control 却缺 --accept-control-replay 时零发送、零输出/报告假成功文件。发送前明确展示站数、协议、control+Probe 最大请求数、正文总字节与 Token 上界和第三方隐私警告。

TSV/stdin/显式环境变量名是 Key 输入；wrapper 不接受 Key 值 argv，不转交明文 Key 参数。私有输入、control 和报告留在 Git/Docker 均排除的目录，输出使用用户专属权限；stdout/stderr/report 不含 Key、私有 URL、绝对用户路径、headers/body 或原始错误文本。无对应 control 的报告不得使用 paired/native-compatible。

## 验证与交付

先以真实 loopback 和自建私有 fixture 红测：原始 body/multi-value headers、单认证、独立阶段和真实分类、models/候选发送次数、fixture 篡改/来源/权限/path/hash/freshness、缺授权零发送/零假输出和报告脱敏。wrapper 使用临时 fake binary 真实执行，证明 argv 无 Key、stdin/文件输入和退出码正确。随后迁移原 CLI 有效回归，运行 cmd/probe/outbound 目标测试、build/vet、脚本合同；不以离线测试冒充真实原生在线矩阵。

设计文档、统一执行链、control 安全输入和 wrapper/文档按可审查边界提交；所有修改仅在本 lane，父代理统一整合和最终 Linux race 验收。
