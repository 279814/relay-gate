# relay-gate v1.0.0 发布说明

发布日：以 `main` 上标注 v1.0.0 的 tag / 本文件合入时间为准。

## 范围声明

本版本按 `docs/01` 分阶段交付。下列「已交付」来自已合并 PR 与各阶段实施记录；
「Deferred」仍属 v1.0.0 目标但**尚未**在本仓库冒充完成。支持的安装形态是 README 中的
HTTP `IP:port` 一行部署（无域名 / ACME / 登录 IP 白名单）。

## 已交付（按阶段）

| 阶段 | 记录 | 合并要点 |
|---|---|---|
| P0 | docs/04 | 探活基础门禁至 P0-17 schema3 cutover / 离线 restore |
| P1 | docs/05 | RecoveryGate、RetryPolicy、duplicate_risk、语义失效、count_tokens 多 Route、Lazy 恢复 |
| P2 | docs/06 | Keyring、凭据 UI/轮换、bootstrap/migrate、HTTP IP:port 一行部署；`acmeip` 状态机与 fake 续期（**未**作安装路径）；登录无 IP 白名单 |
| P3 | docs/07 | 被动扫描旁路、SMTP 假服务器、Active 手动 canary、Security Center |
| P4 | docs/08 | 声明式转换编译器/API/持久化/proxy/UI |
| P5 | docs/09 | 离线发布门禁 `check-p5` + 本说明；旧 sample 信封迁移 |

## 部署入口

- 本机 / Linux 服务器：见根目录 README（`deploy.ps1` / `./deploy.sh` / `docker compose up -d --build`）。
- 首次启动打印 `ADMIN_PASSWORD` / `RELAY_KEYS` / `ENCRYPTION_KEY` 各一次；之后不重复。

## 安全边界（发布时仍成立）

- 默认严格透传；Transform 默认关闭且未绑定不进入转换路径。
- 内容安全默认只告警、不自动改响应或禁用 Route。
- 不提交 `.env`、Keyring、`upstreams.tsv`、`docs/02`、样本正文。
- 管理登录保留失败退避；无登录 IP 白名单。

## 仍 Deferred（诚实清单）

- 需求 §12.2 公网 IP HTTPS / Certbot **真实公网证书签发**（本地状态机与 fake 续期已测；**不得**声称已签发公网证书；当前安装为明文 HTTP）
- 多日生产验证 / 长流压测（本仓库与 CI 时长不允许伪称完成）
- 确认后的旧 sample 明文 dual-read 清理（信封迁移已交付；去掉明文回退需运维确认）

## 最终审查记录

- 请求/响应转换 `fail_closed`：Apply 失败时回滚半截头/body。
- 本说明与 docs/05–09 对齐事实，不冒充公网证书或多日生产验证已完成。
