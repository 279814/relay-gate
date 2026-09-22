# relay-gate v1.0.0 发布说明

发布日：以 `main` 上标注 v1.0.0 的 tag / 本文件合入时间为准。

## 范围声明

本版本按 `docs/01` 分阶段交付。下列「已交付」来自已合并 PR 与各阶段实施记录；
「Deferred」仍属 v1.0.0 目标但**尚未**在本仓库冒充完成。`docs/03-部署与配置.md`
仍是公网域名部署指南，直到公网 IP HTTPS **真实证书签发与容器 smoke** 完成前不得删除。

## 已交付（按阶段）

| 阶段 | 记录 | 合并要点 |
|---|---|---|
| P0 | docs/04 | 探活基础门禁至 P0-17 schema3 cutover / 离线 restore（PR #57） |
| P1 | docs/05 | RecoveryGate、RetryPolicy、duplicate_risk DB 列、重复 model、语义失效、count_tokens 多 Route、Lazy 恢复（PR #58 / #64） |
| P2 | docs/06 | Keyring、凭据 UI/轮换、最近错误、本地一行部署、公网 IP HTTPS **状态机 + 本地 fake Certbot**（PR #59 / #65）；**未**签发真实公网证书 |
| P3 | docs/07 | 被动扫描旁路、SMTP 假服务器、Active 手动 canary、finding 持久化、Security Center 模块（PR #60 / #66） |
| P4 | docs/08 | 声明式编译器/API（PR #61）；schema 6 持久化 + proxy 请求/响应/SSE 已发布绑定（PR #67 / #68 / #71）；Transform 管理 UI（PR #73）；JSON Patch add/remove/copy；body_template |
| P5 | docs/09 | 离线发布门禁 `check-p5` + 本说明；旧 sample 信封迁移（PR #69 / #72） |

## 部署入口

- 本地 / Docker：见根目录 README。
- 公网域名 + 已有 nginx：见 `docs/03-部署与配置.md`。
- 本地一行脚本：`deploy.ps1 -Local` / `./deploy.sh --local`（拒绝未验证的 `--public`）。

## 安全边界（发布时仍成立）

- 默认严格透传；Transform 默认关闭且未绑定不进入转换路径。
- 内容安全默认只告警、不自动改响应或禁用 Route。
- 不提交 `.env`、Keyring、`upstreams.tsv`、`docs/02`、样本正文。

## 仍 Deferred（诚实清单）

- 公网 IP HTTPS / Certbot **真实公网证书签发与容器 smoke**（本地状态机与 fake Certbot 已测；**不得**声称已签发公网证书；docs/03 / Caddyfile / deploy-nginx.sh 保留）
- 多日生产 soak / 长流压测（本仓库与 CI 时长不允许伪称完成）
- 确认后的旧 sample 明文 dual-read 清理（信封迁移已交付；去掉明文回退需运维确认）
- Transform Secret 污点；提高执行预算的二次确认审计
- Runtime Controller 扩展与 README 替换 docs/03 后的删除清单（Caddyfile、deploy-nginx.sh；**真实公网证书验证前不得删**）

## 最终审查记录

- 请求/响应转换 `fail_closed`：Apply 失败时回滚半截头/body；响应路径在写入客户端前失败可返回本地错误（PR #63 / #71）。
- P1–P5 既有 Deferred 收口见 PR #64–#73；本说明与 docs/05–09 对齐事实，不冒充公网证书或多日 soak。
