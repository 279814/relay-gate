# Control 输入内容验收补记

审计用自建 manifest、临时 Git 仓库及 loopback 上游复现：nonce user 旁的任意 system/metadata 会原样重放；responses 可夹带未验收的 messages；request_target 的 query 未参加已知凭据扫描。文件 hash 与 isolation 标记只能证明一致性和来源声明，不能代替内容校验。

本次修复采用端点专用字段合同。messages/count_tokens/chat 只接受 messages，responses 只接受 input；正文中每个可执行字符串都必须是唯一 model、固定 nonce 提示或公开的固定控制 system。可选数值与布尔参数按类型和范围校验，metadata 只接受空对象，thinking 只接受 disabled，stop_sequences 只接受空数组。未知结构及可解释的模板占位符拒绝；原正文在验收后仍只做唯一 model 的字节替换。

capture producer 通过已验证的 --system-prompt 能力显式设置公开控制 system；相同正文/query 合同在导出前验收，不改写或清洗后冒充原始捕获。不知道如何证明安全的原生 metadata/system 必须失败，后续只能通过版本明确的安全结构扩展，不用任意字符串或 UUID 形状猜测私有值。此处离线生产者/读取器兼容回归不证明真实在线原生兼容性。

Query 仅接受现有控制回归所需的 beta=true、mode=fixture 固定参数，可组合但不能重复。检查解码后的键和值及所有已知凭据，拒绝认证参数、业务值、未知参数与模板占位符；验收通过后保留原 RawQuery 字节。

回归先证明危险输入在第一次发送及报告创建前被拒绝，再核对 producer→reader、四端点批准形状、原文/RawQuery 保真、单认证与共享 Executor。最终运行完整 cmd 测试、wrapper 合同、build 和 vet。没有真实用户输入或线上模型请求。
