# relay-gate

[![CI](https://github.com/279814/relay-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/279814/relay-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)

面向多个异构 LLM 中转站的**主动探活 + 优先级路由**透传网关。

手里有几个可用性时好时坏的中转站时，客户端（Claude Code 等）通常要**撞上死站才知道它死了**，
白等一次超时。relay-gate 常驻探活，请求到达时目标渠道的健康状态**已经是已知的**，
直接投递到当前存活且优先级最高的渠道。

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
docker compose logs --no-color 2>&1 | grep -E '^(ADMIN_PASSWORD|RELAY_KEYS|ENCRYPTION_KEY)='
```

之后重启**不会再打印**。若操作员已设置 `ENCRYPTION_KEY` / `RELAY_KEYS` / `ADMIN_PASSWORD`，环境变量优先，不会另造一套。凭据落在 `data/secrets/`（已 gitignore），不要提交进仓库。

### 接上 Claude Code

```bash
export ANTHROPIC_BASE_URL=http://<主机IP>:18787
export ANTHROPIC_AUTH_TOKEN=<RELAY_KEYS 打印出的值>
```

网关三个位置都认凭据（`x-api-key` / `Authorization: Bearer` / `Api-Key`）。

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

需求基线：[docs/01-需求与设计.md](docs/01-需求与设计.md)。阶段记录见 docs/04–09。

## 构建与开发

```bash
go build ./...
go test ./...
go vet ./...
sh scripts/check-p0.sh
sh scripts/check-p5.sh
sh scripts/check-deploy.sh
sh scripts/check-entrypoint.sh
```

Windows 本地不要用 `-race`（无 CGO）。前端是单页 HTML + Alpine.js（`go:embed`），无 Node 构建链。

### 离线备份检查与恢复

```bash
relay-gate db check-backup --database /abs/path/data/relay.db \
  --manifest /abs/path/data/backups/<backup>/manifest.json

relay-gate db restore --database /abs/path/data/relay.db \
  --manifest /abs/path/data/backups/<backup>/manifest.json \
  --execute --accept-data-replacement \
  --accept-reader-contract '<exact-ReaderContract-from-check>'
```

## 安全

- 上游 key 在库中 AES-GCM 加密；样本凭据脱敏
- `.env`、`data/`、`scripts/upstreams.tsv`、`docs/02-上游能力矩阵.md` 已 gitignore
- 备份单位是整个 `data/`（含 Keyring）

发现安全问题请看 [SECURITY.md](SECURITY.md)。

## 贡献

欢迎 issue 与 PR，请先读 [CONTRIBUTING.md](CONTRIBUTING.md)。

## License

[MIT](LICENSE) © LLL
