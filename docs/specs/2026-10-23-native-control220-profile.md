# 固定版本的原生 control profile

实际隔离捕获的 Claude Code 2.1.220 会发送公开程序生成的 system、日期提醒及设备/会话 metadata。既有 format2 内容合同拒绝它们；删除字段再重放不能证明原生兼容。本次增加显式 profile，保留旧 manifest1/format2 合同，不对任意客户端放宽校验。

新 manifest2 的每条 entry 必须声明 profile。`legacy-format2-v1` 明确选择旧合同；`claude-code-2.1.220-windows-isolated-v1` 只接受 format3、Windows x64、Messages、精确版本和已审查可执行文件 SHA-256 `af5bf1f1b2aadffc768eccd787084c6fdf9ba81624cbe96c1c6d9ac1a1550231`。manifest1 不允许新增 profile，即使为 null/空字符串。未知版本、格式混用、test_mode 和 2.1.296 的不透明字段继续拒绝。普通代理的客户端版本支持不受此专用验收格式限制。

新生产者 `scripts/capture-claude220-control.ps1` 必须显式给出客户端路径和 Execute。它先验收私有 Git/Docker 忽略目录及当前用户 ACL，固定二进制 hash，并持有禁止写入/替换的只读句柄。新建位于工作区磁盘根目录的独立临时目录，检查祖先没有项目定制文件；使用空子进程环境加操作系统必要项、独立 HOME/config/temp 和仅内存 fake key。显式关闭配置来源、MCP、工具、hook/plugin、浏览器及持久会话。既有用户配置不读取，不修改默认客户端、注册表或全局环境。已有目录权限过宽直接拒绝，不替用户递归修改 ACL。

两个边界分别在导出前和生产读取时验证完整内容：

- Body 固定九个字段、64 输出 Token、thinking disabled、effort low、stream true、空 tools 数组、三个 system 和一个两块 user message；未知键、重复键、null/额外结构均拒绝。
- 固定 system/public date 模板用已审查程序构造的 SHA-256 验证。日期只允许捕获 UTC 日及相邻一天，正文其余部分固定。billing suffix 来自该版本公开程序常量、版本及专用 nonce prompt；不是任意十六进制字符串放行。
- 临时 config 的设备 ID 为 SHA256(`relay-gate-control-device-v1:` + nonce)。会话 ID 为 SHA256(`relay-gate-control-session-v1:` + nonce) 前16字节设置 UUIDv4 位，按网络字节序格式化。metadata 必须恰有这两个派生值和空字符串 account_uuid；不接受真实账户值，也不按 UUID 形状推测安全。
- Headers 必须恰有21个单值条目，SDK/OS/运行时/beta/timeout 均为该版本实测固定值；session 与 nonce 派生值一致，Host 只能是有效 loopback 端口，Content-Length 必须正确。认证先验证 fake key，导出只替换为既有类型化占位符；顺序和正文原字节不变。目标只允许 `/v1/messages` 或 `?beta=true`。

读取后沿用生产 Resolver、Executor、Decoder、认证及出站头保护。仍只替换目标 URL/Host/认证及必要 model，不新增旁路 client。所有现有时窗、文件保护、hash、已知凭据扫描及发送前重新校验继续生效。捕获文件里的 hash/来源声明本身不是签名，不能代替可信的本次生产者执行证据。

用法（PowerShell 7.2+，显式固定版本路径，不含密钥）：

```powershell
./scripts/capture-claude220-control.ps1 -ClaudePath <reviewed-2.1.220-executable> `
  -OutputPath <repository>/.local/p0/controls/control.json `
  -ManifestPath <repository>/.local/p0/controls/manifest.json -Alias <test-alias> -Execute
```

已有 `.local/p0/` 各级目录需先满足私有权限；新目录由脚本创建并设置。输出文件必须不存在、相邻且不同。失败保留已成功写出的私有文件供排查，不删除用户 control。私有捕获、输入、报告不提交。

2026-10-23 本机实际固定版本完成回环请求及正常退出，生成的1117字节原始正文经生产读取器验证，过期61秒拒绝；验证归档文件时仅测试注入捕获完成后一秒的时间，不延长生产60秒时窗。对照请求只发到本机假上游，真实模型请求为0；不能据此宣称线上原生兼容。公开 testdata 明确标为合成合同 fixture，不是原生运行证据。回归覆盖生产者→读取器保真、旧合同边界、私有字段/身份/未知 header/重复键拒绝、宽目录 ACL/错误二进制拒绝，以及 shared Executor 先 control 后 probe 的真实 HTTP 流程。Responses/Chat 仍须隔离的 CC Switch 对照，缺少时继续 control_missing。
