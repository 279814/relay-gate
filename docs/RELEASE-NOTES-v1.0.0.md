# relay-gate v1.0.0 发布说明

状态：本文件记录 v1.0.0 目标的交付范围，不等于正式版本已发布；正式发布以 GitHub Release 与对应 tag 为准。当前验收与交接见 [维护与交接](10-维护与交接.md)。

## 范围声明

本版本按 `docs/01` 分阶段实现。下列范围描述当前代码，不表示所有最终验收已完成；历史阶段记录中的 Deferred 也需结合[完成矩阵](11-最终完成矩阵.md)核对。默认安装为 HTTP `IP:port`，Linux 可显式选择独立公网 IP HTTPS 入口；后者的真实公网签发仍待相应主机验收。两种入口均不要求域名或管理登录 IP 白名单。

## 当前实现（按阶段）

| 阶段 | 记录 | 代码范围 |
|---|---|---|
| P0 | docs/04 | 统一探活与真实流量观察、Recipe/Profile 管理、分页与客户端 CAS、schema 8 数据密钥及离线恢复；最终门禁状态见完成矩阵 |
| P1 | docs/05 | RecoveryGate、RetryPolicy、duplicate_risk、语义失效、count_tokens 多 Route、Lazy 恢复 |
| P2 | docs/06、docs/13 | Keyring、凭据 UI/轮换、bootstrap/migrate、默认 HTTP 与独立 Certbot/Nginx 公网 IP HTTPS 部署；真实公网签发尚未验收；登录无 IP 白名单 |
| P3 | docs/07 | 被动扫描旁路、SMTP 假服务器、Active 手动 canary、Security Center |
| P4 | docs/08 | 声明式转换编译器/API/持久化/proxy/UI |
| P5 | docs/09 | 离线发布门禁 `check-p5` + 本说明；旧 sample 信封迁移 |

## 部署入口

- 本机 / Linux 服务器：见根目录 README（`deploy.ps1` / `./deploy.sh` / `docker compose up -d --build`）。
- Linux 公网入口：`sudo ./deploy.sh --public` 后交互确认；自动化时同时提交 `--ip` 与相同的 `--confirm-ip`。详见[公网 IP HTTPS](13-公网IP-HTTPS.md)。
- 首次启动打印 `ADMIN_PASSWORD` / `RELAY_KEYS` / `ENCRYPTION_KEY` 各一次；之后不重复。

## 安全边界（发布时仍成立）

- 默认严格透传；Transform 默认关闭且未绑定不进入转换路径。
- 内容安全默认只告警、不自动改响应或禁用 Route。
- 不提交 `.env`、Keyring、`upstreams.tsv`、`docs/02`、样本正文。
- 管理登录保留失败退避；无登录 IP 白名单。
- 管理页面登出会清空各功能的数据与草稿；旧会话的响应不能重新填回凭据或证据。Settings / RunState 写入各自固定客户端版本，冲突须显式重载；503 的 `persisted=true` 表示提交已发生，不能按回滚自动重发。

## 仍 Deferred（诚实清单）

- 需求 §12.2 公网 IP HTTPS / Certbot **真实公网证书签发**（生产 Certbot/Nginx 路径与可信边缘已实现，见 [公网 IP HTTPS](13-公网IP-HTTPS.md)；**不得**声称已签发公网证书，仍需真实主机验收）
- 最终目标提交的长流与 48 小时持续运行验证；已有开发版长流／本地 CA 记录与已记录的失败结果，均不能替代最终通过证据，见[实际时长验收](15-实际时长验收.md)
- 最终目标提交下的故障恢复、实际长流、容器与三平台二进制联合验收。

## 数据密钥与恢复补充

schema 8 引入独立 Sample / Security Data Key、认证 v2/v2m 正文和严格旧格式迁移；Master Key 轮换只重包数据密钥及直接秘密，不重写正文。数据库与凭据归档按 manifest 配对恢复，支持显式 `--use-backup-keyring` 恢复旧密钥备份。自动恢复在首次凭据生成前完成。说明与运维边界见 [数据密钥与恢复](12-数据密钥与恢复.md)。这不代表历史备份、WAL 或磁盘空闲页已被安全擦除。

## 最终审查记录

- 请求/响应转换 `fail_closed`：提交前失败不发送半成品；已提交的流只终止，不追加本地错误 JSON 或换站重发。SSE 在可决响应头提交后初始化流解码，坏编码按提交后错误处理；真正 JSON 正文转换保留完整缓冲与提交前失败策略。
- 本说明与 docs/05–09 对齐事实，不冒充公网证书或多日生产验证已完成。
