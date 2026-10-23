# relay-gate

[![CI](https://github.com/279814/relay-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/279814/relay-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go)](go.mod)

面向多个异构 LLM 中转站的**主动探活 + 优先级路由**透传网关。

手里有几个可用性时好时坏的中转站时，客户端（Claude Code 等）通常要**撞上死站才知道它死了**，
白等一次超时。relay-gate 通过后台探活与真实流量观察维护健康状态，按有效结论与优先级选路；
Active 站点周期复核，Lazy 站点按需复核，未知或过期的结论按恢复规则处理。

```
Claude Code ──▶ relay-gate ──▶ 站 A（优先级 1，健康）✅
                    │
                    ├── 探活中：站 B（优先级 2，健康）
                    └── 探活中：站 C（优先级 3，已判死，不投递）
```

## 它代理什么

入站路径 = 出站路径，**不做协议转换**。支持：

| 端点 | 说明 |
|---|---|
| `POST /v1/messages` | Anthropic Messages |
| `POST /v1/responses` | OpenAI Responses |
| `POST /v1/chat/completions` | OpenAI Chat Completions |
| `POST /v1/messages/count_tokens` | 上游优先，不支持时本地估算兜底 |
| `GET /v1/models` | 本地应答，返回已配置的逻辑模型 |
| `GET /healthz` | 进程存活 + 版本 + 总闸状态 |

鉴权：客户端使用本服务发放的 **relay key**（不是上游站的 key）。管理界面用管理员口令。

## 一行安装（HTTP `IP:port`）

需要 **Docker** 与 **Docker Compose**。访问形态是 `http://<主机IP>:18787`，
**不需要域名、证书、ACME 邮箱、SMTP，也没有登录 IP 白名单**。

### 本机（Windows / macOS / Linux）

```powershell
git clone https://github.com/279814/relay-gate.git
cd relay-gate
.\deploy.ps1
```

或（任意已装 Docker 的系统）：

```bash
git clone https://github.com/279814/relay-gate.git
cd relay-gate
docker compose up -d --build
```

### Linux 服务器

```bash
git clone https://github.com/279814/relay-gate.git
cd relay-gate
./deploy.sh
```

默认端口 **18787**（可用 `.env` 里的 `RELAY_PORT` 覆盖）。打开：

```text
http://<这台机器的IP>:18787/admin/
```

### 首次启动的三项密钥

若未在环境变量里设置凭据，**第一次启动**会生成并**只打印一次**到控制台 / 容器日志：

| 打印行 | 含义 |
|---|---|
| `ADMIN_PASSWORD=` | 管理界面口令 |
| `RELAY_KEYS=` | 发给客户端的 relay key |
| `ENCRYPTION_KEY=` | 上游 key 的加密主密钥（Master Key） |

查看（Compose）：

```bash
docker compose logs --no-color --no-log-prefix 2>&1 | grep -E '^(ADMIN_PASSWORD|RELAY_KEYS|ENCRYPTION_KEY)='
```

之后重启**不会再打印**。若操作员已设置 `ENCRYPTION_KEY` / `RELAY_KEYS` / `ADMIN_PASSWORD`，环境变量优先，不会另造一套。凭据落在 `data/secrets/`（已 gitignore），不要提交进仓库。

### 接上 Claude Code

```bash
export ANTHROPIC_BASE_URL=http://<主机IP>:18787
export ANTHROPIC_AUTH_TOKEN=<RELAY_KEYS 打印出的值>
```

网关三个位置都认凭据（`x-api-key` / `Authorization: Bearer` / `Api-Key`）。

### 管理设置与启停版本

管理页面会保留编辑时读取的版本。自行调用管理 API 时，先读取版本，再随写请求提交正整数 `expected_revision`：

| 操作 | 读取与写入 |
|---|---|
| 全局设置 | `GET /admin/api/settings` 返回 `{settings, revision, limits}`；`PUT /admin/api/settings` 提交变更字段及该 `expected_revision`，省略字段保持原值 |
| 服务启停 | `GET /admin/api/state` 返回独立 `revision`；`POST /admin/api/state` 提交 `state`（`running` 或 `paused`）及该 `expected_revision` |

缺少有效版本返回 400，旧版本返回 409。设置只接受新的分阶段字段，例如 `real_first_semantic_sec`、`count_tokens_connect_sec`、`count_tokens_total_sec`；旧 `real_first_token_sec`、`l2_first_token_sec`、`count_tokens_sec` 仅用于启动时迁移，不能写入 API。设置与启停使用各自的版本，不能混用。

503 若带 `persisted=true` 和 `new_revision`，表示已持久化、激活或暂停 drain 尚待完成；先重新读取并确认，不用旧版本自动重发。页面遇到冲突或激活待确认时会保留草稿，并要求显式重新加载。登出会清空已加载的凭据、证据与编辑状态；样本原文另需显式再次验证口令。

### 单独测一个中转站（probe-matrix）

不启动网关，直接对 sub2api / New API / One API 等中转站测 `/v1/models`、`/v1/messages`、
`/v1/messages/count_tokens`、`/v1/responses`（及 chat），逐端点打印 `PASS` / `FAIL`。
会产生真实费用：每站 `/models` 一次，每个 Claude 模型的 messages/count_tokens 各一次，每个 GPT 模型的 responses/chat 各一次；无隐藏重试。必须显式加 `--online --accept-probe-cost`。
key 只从环境变量或被 gitignore 的 TSV 读，不走命令行参数：

```powershell
$env:RELAY_KEY = '<该站 key>'
go run ./cmd/relay-gate probe-matrix --online --accept-probe-cost `
  --base-url https://relay.example.com --key-env RELAY_KEY `
  --claude-model claude-opus-5 --gpt-model gpt-5.6-sol
```

模型 ID 应替换为该站实际支持的值。多个模型用逗号分隔。多站批量按 `scripts/upstreams.example.tsv` 填 `scripts/upstreams.tsv`；文件还须只有当前用户可读，并被 Git/Docker 同时排除。wrapper 与 CLI 使用相同的命名参数，不自动补费用授权，也不接受旧的明文 Key 位置参数：

```bash
umask 077
mkdir -p .local/p0/reports
chmod 600 scripts/upstreams.tsv
bash scripts/probe-all.sh --online --accept-probe-cost \
  --input scripts/upstreams.tsv \
  --output .local/p0/reports/matrix.json --report .local/p0/reports/matrix.md
# 单站：同样的参数，加 --name <TSV中的alias>
bash scripts/probe-upstream.sh --online --accept-probe-cost \
  --input scripts/upstreams.tsv --name "<alias>"
```

也可用 `--input -` 从 stdin 读取 TSV。报告目录须预先存在、仅当前用户可访问；Windows 还会检查 ACL。stdout/report 只含 alias、决策、阶段时间、版本、成本和临时密钥保护的证据哈希，响应哈希明确表示实际观察到的 wire 前缀。

没有对应 control 时只报告 `control_missing`，Probe 自身 PASS 不代表与原生一致。重放专用 control 必须额外提供 `--control-manifest <私有manifest> --accept-control-replay`，每个有 control 的候选另外发送一次原始 control。工具会在第一次发送前报告总请求数和成本估算，并在实际发送层守住捕获完成后 60 秒期限。

Windows 的隔离 Claude capturer 可同时写出 typed v2 fixture 和相邻 manifest：先为 `.local/p0/captures` 准备当前用户专属权限，再运行 `pwsh -File scripts/capture-claude-request.ps1 -Execute -AllowedRoot <私有目录> -OutputPath <同目录的新fixture.json> -ManifestPath <同目录的新manifest.json> -Alias <TSV中的alias>`。它只用空临时目录、隔离配置和 loopback 假上游捕获固定 nonce 提示，不调用真实模型；旧 v1 capture 或 `test_mode` 文件不能充当原生证据。CLI 会重读 fixture，校验来源/隔离声明、原始有序 headers/body 哈希、权限和完整性，再使用生产 Executor 真实执行 control 与 Probe。OpenAI control 同样必须来自可证明隔离的本次专用会话；没有该证据时保留 `control_missing`，不从历史样本补齐。

Control 还逐值校验内容：每个端点只接受对应的单条 nonce 输入、有限类型参数及批准的 SDK/协议头；system 只接受 capturer 显式设置的公开控制句 `Reply with 2 only.`，metadata 必须为空，thinking 只接受 disabled。认证只能在唯一的占位符认证头，query 仅允许 `beta=true`、`mode=fixture` 固定参数。未知业务正文、header、query、会话元数据或大小写别名均拒绝；不会清洗后冒充原始捕获。未批准的原生版本或结构需重新验收，本地合成回归不证明真实原生兼容。

## 为什么不是「重试就行了」

被动 failover（请求失败再换下一个）在长思考场景下代价很高：一次首 Token 超时可能是
20 分钟。主动探活把发现故障的代价挪到请求之外。

## 设计要点

| 主题 | 结论 |
|---|---|
| 改写范围 | 仅鉴权头（必改）+ body 顶层 `model`（配了映射才改） |
| 数据模型 | Upstream / ModelName / Route（优先级与健康状态最小单位） |
| 存储 | 单副本 SQLite（`modernc.org/sqlite`，无 CGO），库权限 0600 |
| 登录保护 | 失败退避（按来源 IP + 全局）；**无**登录 IP 白名单 |

需求基线：[docs/01-需求与设计.md](docs/01-需求与设计.md)。阶段记录见 docs/04–09；当前验收边界与交接步骤见 [维护与交接](docs/10-维护与交接.md)、[完成矩阵](docs/11-最终完成矩阵.md)与[P0实现索引](docs/18-P0-实现与验收索引.md)。Recipe与ClientProfile操作见[管理说明](docs/16-Recipe与ClientProfile管理.md)。

## 构建与开发

```bash
go build ./...
go test -timeout=20m -count=1 ./...
go vet ./...
bash scripts/check-p0.sh
bash scripts/check-p5.sh
sh scripts/check-deploy.sh
sh scripts/check-entrypoint.sh
node internal/web/bindings.check.js
node internal/web/app.contract.test.js
node internal/web/configadmin.contract.test.js
node internal/web/manual-probe.contract.test.js
node --test internal/web/modules.contract.test.mjs
node --test internal/web/recipe_admin.contract.test.mjs internal/web/settings.contract.test.mjs internal/web/state.contract.test.mjs internal/web/privacy.contract.test.mjs internal/web/endpoint.contract.test.mjs
python scripts/deploy.contract.test.py
python scripts/deploy-public.contract.test.py
```

Go 版本以 `go.mod` 为准。检查脚本需要 Bash、Python 3、Node.js 和 PowerShell 7（`pwsh`）；它们只用于验证，运行服务不需要。Windows 无 CGO 时不要用 `-race`，竞态检测与容器冒烟由 Linux CI 执行。前端是单页 HTML + Alpine.js（`go:embed`），无 Node 构建链。

### 公网 IP HTTPS

Linux 公网部署支持 `sudo ./deploy.sh --public`，交互确认本机公网 IP；自动化部署须同时提供 `--ip <公网IP> --confirm-ip <相同公网IP>`。仅 Nginx 边缘发布 80/443，后端保持私网访问。签发与链/SAN/私钥/有效期校验成功前只提供 ACME 挑战；证书续期独立于网关暂停状态。命令、恢复与验收边界见 [公网 IP HTTPS](docs/13-公网IP-HTTPS.md)。真实 Nginx／本地 CA 测试不能证明公网证书已签发；真实公网验收与最终目标提交的长流、48 小时持续运行记录仍需分别完成，见 [实际时长验收](docs/15-实际时长验收.md)。

### 离线备份检查与恢复

先停止容器或二进制进程，并备份完整 `data/`（SQLite、WAL/SHM 与 `secrets/` 一起保留）。确认备份 manifest 指定的配对 image/binary 可用，再执行只读检查；不要在服务运行时直接复制或覆盖数据库。

```bash
relay-gate db check-backup --database /abs/path/data/relay.db \
  --manifest /abs/path/data/backups/<backup>/manifest.json
```

离线命令默认只读取 `--database` 所在目录的 `secrets/keyring.json` 稳定 active Master，不依赖当前工作目录、`RELAY_DB`、管理员口令或 Relay Key。非空 `ENCRYPTION_KEY` 显式覆盖该选择；错误的覆盖值会拒绝检查，不会静默回退。目标 Keyring 缺失、格式/状态未知或轮换未完成时拒绝，不恢复 `keyring.previous`、不激活 pending Master，也不启动服务。

核对检查输出的 `ReaderContract` / `PairedBuildID` 与配对程序后，再显式接受数据替换：

```bash
relay-gate db restore --database /abs/path/data/relay.db \
  --manifest /abs/path/data/backups/<backup>/manifest.json \
  --execute --accept-data-replacement \
  --accept-reader-contract '<exact-ReaderContract-from-check>'
```

使用输出要求的配对 image/binary 启动并检查 `/healthz`；恢复会保留原数据库的隔离目录，不要在验证前删除。schema 3→2 需要 manifest 指定的 P0 compatible reader；恢复 schema 1 到 pre-P0 程序会放弃该备份之后的新配置。完整限制见需求基线中的恢复章节。

schema 8 备份将数据库和 `secrets/` 配对保存。轮换之后恢复旧 Master Key 的备份时，可在上述两个命令中显式加 `--use-backup-keyring`，仅使用经 manifest 哈希校验并与数据库配对的归档 active Master；默认仍使用当前配置并在不匹配时拒绝。恢复命令仍需全部数据替换授权。备份中的 `secrets.json` 含真实密钥，应按敏感文件保管。迁移与恢复契约见 [数据密钥与恢复说明](docs/12-数据密钥与恢复.md)。

## 安全

- 上游 key 和样本正文使用 AES-GCM 加密；路径、脱敏请求头等元数据并非整库加密，管理 API 经授权仍能读出对话原文
- `.env`、`data/`、`scripts/upstreams.tsv`、`docs/02-上游能力矩阵.md` 已 gitignore
- 备份单位是整个 `data/`（含 Keyring）；Master Key 通过管理界面的轮换流程更新，不能直接替换环境变量

发现安全问题请看 [SECURITY.md](SECURITY.md)。

## 贡献

欢迎 issue 与 PR，请先读 [CONTRIBUTING.md](CONTRIBUTING.md)。

## License

[MIT](LICENSE) © LLL
