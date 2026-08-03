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

## 为什么不是"重试就行了"

被动 failover（请求失败再换下一个）在长思考场景下代价很高：一次首 Token 超时可能是
20 分钟，而用户看到的是 20 分钟的空白。主动探活把这个代价挪到了请求之外。

| | 被动 failover | relay-gate |
|---|---|---|
| 何时发现站挂了 | 用户的请求撞上去时 | 探活周期内（实测 1.5–2.0s） |
| 用户感知 | 白等一次超时 | 无感，直接投到健康站 |
| 假活（HTTP 200 但不出内容） | 认为可用 | 判死 —— 必须收到首个**非空内容 delta** 才算活 |

## 三条主线

1. **主动探活** —— 两级探测（传输层零 token + 模型层真实调用），状态在请求到达前已知
2. **严格透传** —— 除鉴权 key 与 `model` 外，请求一个字节都不改；响应完全不碰
3. **样本留档** —— 每次转发的入站请求、出站请求、上游响应全部存下来，
   既验证第 2 条真做到了，也让探活请求长得和真实请求一样

## 快速开始

需要 Docker 与 Docker Compose。

```bash
git clone https://github.com/279814/relay-gate.git
cd relay-gate
cp .env.example .env
```

填 `.env` 里的三项必填（缺任何一项都会**拒绝启动**，而不是带着空 key 跑起来）：

```bash
ENCRYPTION_KEY=$(openssl rand -hex 32)    # 加密上游 key。丢了 = 已存的 key 全部解不开
RELAY_KEYS=rk-$(openssl rand -hex 24)     # 发给客户端的 key，不是上游站的
ADMIN_PASSWORD=$(openssl rand -base64 24) # 管理界面口令
```

```bash
docker compose up -d
```

端口只绑 `127.0.0.1:18787`，管理界面在 <http://127.0.0.1:18787/admin/>。
在界面里配上游站、逻辑模型、路由优先级。

需要**服务器公网访问 + 多中转站 + Claude Code 接入 + 运维**的逐步示例，
请直接看 [服务器部署与配置](docs/03-部署与配置.md)。
服务器上**已有 nginx + 证书**（80/443 被占用）的话，用其中
[第 14 章的一键脚本](docs/03-部署与配置.md#14-已有-nginx--证书的服务器一键脚本)：
```bash
curl -sSL https://raw.githubusercontent.com/279814/relay-gate/main/scripts/deploy-nginx.sh | sh
```
脚本自动生成凭据与 nginx 反代、扩证书 SAN，全程无需编辑文件，
中转站配置走网页管理界面。

### 接上 Claude Code

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:18787
export ANTHROPIC_AUTH_TOKEN=rk-你生成的那个
```

网关三个位置都认凭据（`x-api-key` / `Authorization: Bearer` / `Api-Key`），
所以 `ANTHROPIC_API_KEY` 同样可用。

### 对公网提供服务

```bash
# .env 里再填 RELAY_DOMAIN、RELAY_ALLOW_IPS（留空 = 管理面全部 403，刻意如此）
docker compose --profile public up -d
```

Caddy 负责 TLS 与证书自动续期，并对管理面做 IP 白名单。转发端点不限 IP，靠 relay key 鉴权。

> [!WARNING]
> **把这个服务裸奔到公网 = 一个无鉴权的免费 API 池。** 必须设置 relay key。
> 端口刻意只绑 `127.0.0.1` —— 写成 `18787:18787` 的话 Docker 会插一条 iptables 规则
> 把它**直接暴露到公网，且绕过 ufw/firewalld**（你在防火墙里看不到）。

## 支持的端点

入站路径 = 出站路径，**不做协议转换**。

| 端点 | 说明 |
|---|---|
| `POST /v1/messages` | Anthropic Messages |
| `POST /v1/responses` | OpenAI Responses |
| `POST /v1/chat/completions` | OpenAI Chat Completions |
| `POST /v1/messages/count_tokens` | 上游优先，不支持时本地估算兜底 |
| `GET /v1/models` | 本地应答，返回已配置的逻辑模型 |
| `GET /healthz` | 进程存活 + 版本 + 总闸状态（不代表有可用上游） |

## 设计要点

| 主题 | 结论 |
|---|---|
| 改写范围 | 仅鉴权头（必改）+ body 顶层 `model`（配了映射才改）。字节级切片替换，不做 JSON round-trip |
| 数据模型 | 三层：Upstream（站）/ ModelName（逻辑模型）/ Route（绑定，含优先级与映射）。Route 是健康状态的最小单位 |
| 首 Token 超时 | 默认 20 分钟，**硬下限 5 分钟**。探活超时独立配置，因此「容忍长思考」与「快速判死」可以同时成立 |
| 死站恢复 | 固定短周期（L1 20s / L2 30s）+ L1 转通即触发 L2 + 半开放行，不用指数退避 |
| 假活检测 | HTTP 200 不算活。必须收到首个**非空内容 delta** 才算 |
| 请求内重试 | 未写出字节前可换站重试，逐次尝试都留档 |
| 存储 | 单副本 SQLite（`modernc.org/sqlite`，无 CGO），库文件权限 0600 |

完整设计与各阶段实际完成范围见 [需求与设计文档](docs/01-需求与设计.md)。

部署到公网、配置多个中转站、验证故障切换、接入 Claude Code、备份与排障：
见 [服务器部署与配置](docs/03-部署与配置.md)。

## 项目状态

功能已完整，可部署。M0–M7 全部完成。

仍待真实流量验证的三项（都需要接上 Claude Code 才能做）：
`/v1/responses` 的上游支持性复测、`count_tokens` 本地估算的精度校准、
公网模式下长思考不被 Caddy 中途掐断（配置已通过 `caddy validate`，
但「解析器接受」不等于「运行时按预期生效」）。

## 目录结构

```
cmd/relay-gate/   入口：启动、优雅关闭、依赖装配
internal/         proxy 透传 / probe 探活 / health 状态机 / router 选路 /
                  store SQLite / api 管理端 / web 内嵌界面
deploy/           Caddyfile 与容器 entrypoint
docs/             需求与设计文档
scripts/          能力探测、各阶段冒烟、部署静态检查
```

## 开发

```bash
go build ./...
go test ./...
go vet ./...
```

前端是单页 HTML + Alpine.js，通过 `go:embed` 打进二进制 —— 没有构建链，
改完直接 `go build`。

验证部署改动：

```bash
sh scripts/check-entrypoint.sh   # entrypoint 的静态不变量，无需 Docker
sh scripts/check-deploy.sh       # 部署清单的静态不变量，无需 Docker
pwsh -File scripts/smoke-m7.ps1  # 容器端到端，需要 Docker 引擎
```

三项都在 CI 里跑（前两个在 `test` job，第三个在独立的 `container` job）。
容器那一项验的每一条（0600 库权限、PID 1 是谁、SIGTERM 直达、端口只绑
`127.0.0.1`、空 ACME 邮箱、空 IP 白名单）都**只在容器里**才成立或才会坏，
本地 `go test` 全绿证明不了其中任何一条。

### 探测上游能力（可选）

写代码前先实测各站到底支持什么：

```bash
cp scripts/upstreams.example.tsv scripts/upstreams.tsv
# 编辑 upstreams.tsv（Tab 分隔，含真实 key，已在 .gitignore 中）
bash scripts/probe-all.sh scripts/upstreams.tsv
```

输出能力矩阵到 `docs/02-上游能力矩阵.md`（同样已 gitignore，含站点地址）。
单站约消耗 100 token。探测项包括鉴权头风格、模型名原名是否可用、
流式真活/假活、首 Token 延迟、`count_tokens` 与 `/v1/responses` 支持情况。

## 安全

- 上游 key 在数据库中 **AES-GCM 加密**存储；样本里的凭据脱敏
- 库文件与 WAL 权限收到 **0600** —— 样本里有**明文的**对话原文，加密只保护了上游 key
- `.env`、`data/`、`scripts/upstreams.tsv`、`docs/02-上游能力矩阵.md` 已全部 gitignore
- 备份只需 `data/` 目录：上游配置、样本、请求日志、健康历史全在里面

发现安全问题请看 [SECURITY.md](SECURITY.md)。

## 贡献

欢迎 issue 与 PR，请先读 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 技术栈

Go 1.26 / `net/http` + `httputil.ReverseProxy` / SQLite（`modernc.org/sqlite`，无 CGO）/
单页 HTML + Alpine.js（`go:embed`）/ Docker Compose 单容器部署。

## License

[MIT](LICENSE) © LLL
