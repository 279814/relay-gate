# relay-gate

面向多个异构 LLM 中转站的**主动探活 + 优先级路由**透传网关。

解决的问题：手里有多个可用性时好时坏的中转站，客户端（Claude Code 等）撞上死站
才知道它死了，白等一次超时。本服务常驻探活，请求到达时目标渠道的健康状态**已经是已知的**，
直接投递到当前存活且优先级最高的渠道。

## 三条主线

1. **主动探活** —— 两级探测（传输层零 token + 模型层真实调用），状态在请求到达前已知
2. **严格透传** —— 除鉴权 key 与 `model` 外，请求一个字节都不改；响应完全不碰
3. **样本留档** —— 每次转发的入站请求、出站请求、上游响应全部存下来，
   既验证第 2 条真做到了，也让探活请求长得和真实请求一样

## 状态

功能已完整，可部署。各阶段的实际完成范围与偏离说明见
[需求与设计文档](docs/01-需求与设计.md) 的里程碑一节。

- [x] M0 实测上游能力
- [x] M1 骨架 + SQLite + 配置 CRUD
- [x] M2 透传核心 + 选路 + 样本记录
- [x] M3 探活 + 健康状态机
- [x] M4 其余端点
- [x] M5 Web UI + 一键启停
- [x] M6 请求内重试 + 日志
- [x] M7 Docker Compose 部署

仍待真实流量验证的两项（都需要接上 Claude Code 才能做）：
`/v1/responses` 的上游支持性复测、`count_tokens` 本地估算的精度校准。

## 设计要点

| 主题 | 结论 |
|---|---|
| 协议 | Anthropic Messages / OpenAI Responses / OpenAI Chat Completions，入站路径 = 出站路径，**不做协议转换** |
| 改写范围 | 仅鉴权头（必改）+ body 顶层 `model`（配了映射才改）。字节级切片替换，不做 JSON round-trip |
| 数据模型 | 三层：Upstream（站）/ ModelName（逻辑模型）/ Route（绑定，含优先级与映射）。Route 是健康状态的最小单位 |
| 首 Token 超时 | 默认 20 分钟，**硬下限 5 分钟**。探活超时独立配置，因此「容忍长思考」与「快速判死」可以同时成立 |
| 死站恢复 | 固定短周期（L1 20s / L2 30s）+ L1 转通即触发 L2 + 半开放行，不用指数退避 |
| 假活检测 | HTTP 200 不算活。必须收到首个**非空内容 delta** 才算，否则是公益站最常见的假活 |

## 目录

```
cmd/relay-gate/   入口：启动、优雅关闭、依赖装配
internal/         proxy 透传 / probe 探活 / health 状态机 / router 选路 /
                  store SQLite / api 管理端 / web 内嵌界面
deploy/           Caddyfile 与容器 entrypoint
docs/             需求与设计文档
scripts/          M0 探测脚本、各阶段冒烟、部署静态检查
```

## 部署

```bash
cp .env.example .env
# 填三项必填：ENCRYPTION_KEY / RELAY_KEYS / ADMIN_PASSWORD
# 缺任何一项都会拒绝启动，而不是带着空 key 跑起来
docker compose up -d
```

端口只绑 `127.0.0.1:18787`，管理界面在 `http://127.0.0.1:18787/admin/`。

要对公网提供服务时加 `--profile public`，由 Caddy 做 TLS 与管理面 IP 白名单：

```bash
# .env 里再填 RELAY_DOMAIN、RELAY_ALLOW_IPS（留空 = 管理面全部 403）
docker compose --profile public up -d
```

**唯一需要备份的是 `data/` 目录** —— 上游配置、样本、请求日志、健康历史全在里面。
库文件权限是 0600（里面有明文的对话原文，加密只保护了上游 key）。

验证部署改动：

```bash
sh scripts/check-entrypoint.sh   # entrypoint 的静态不变量，无需 Docker
sh scripts/check-deploy.sh       # 部署清单的静态不变量，无需 Docker
pwsh -File scripts/smoke-m7.ps1  # 容器端到端，需要 Docker 引擎
```

## M0：探测上游能力

写代码前先实测各站到底支持什么。复制模板填入自己的站点：

```bash
cp scripts/upstreams.example.tsv scripts/upstreams.tsv
# 编辑 upstreams.tsv（Tab 分隔，含真实 key，已在 .gitignore 中）
bash scripts/probe-all.sh scripts/upstreams.tsv
```

输出能力矩阵到 `docs/02-上游能力矩阵.md`（同样已 gitignore，含站点地址）。
单站约消耗 100 token。

探测项：`/v1/models` 可用性、鉴权头风格（`x-api-key` / `Bearer`）、模型名原名是否可用、
流式真活/假活、首 Token 延迟、`count_tokens` 支持情况、`/v1/responses` 支持情况、
长思考首 Token 延迟（用于校准超时）。

## 安全

- `scripts/upstreams.tsv`、`*.local.tsv`、`docs/02-上游能力矩阵.md`、`data/`、`.env`
  已全部 gitignore。**不要**把真实 key 或站点地址提交上来
- 上游 key 在数据库中 AES-GCM 加密存储
- 服务暴露到公网 = 一个无鉴权的免费 API 池。必须设置 relay key，
  并且只监听内网 + 反向代理，或加 IP 白名单

## 技术栈

Go 1.24+ / `net/http` + `httputil.ReverseProxy` / SQLite（`modernc.org/sqlite`，无 CGO）/
单页 HTML + Alpine.js（`go:embed`）/ Docker Compose 单容器部署。
