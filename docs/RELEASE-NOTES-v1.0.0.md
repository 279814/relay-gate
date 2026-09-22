# relay-gate v1.0.0 发布说明

发布日：以 `main` 上标注 v1.0.0 的 tag / 本文件合入时间为准。

## 范围声明

本版本按 `docs/01` 分阶段交付。下列「已交付」来自已合并 PR 与各阶段实施记录；
「Deferred」仍属 v1.0.0 目标但**尚未**在本仓库冒充完成。`docs/03-部署与配置.md`
仍是公网域名部署指南，直到公网 IP HTTPS 验证完成前不得删除。

## 已交付（按阶段）

| 阶段 | 记录 | 合并要点 |
|---|---|---|
| P0 | docs/04 | 探活基础门禁至 P0-17 schema3 cutover / 离线 restore（PR #57） |
| P1 | docs/05 | RecoveryGate、RetryPolicy、duplicate_risk、重复 model 拒绝（PR #58） |
| P2 | docs/06 | Keyring 文件根、最近错误弹窗、本地一行部署入口（PR #59）；**未**验证公网 IP 证书 |
| P3 | docs/07 | 被动扫描 + Security Center API（PR #60）；SMTP / 主动 canary 延后 |
| P4 | docs/08 | 声明式转换编译器、Registry、管理 API（PR #61）；SQLite 持久化与 proxy 全接线延后 |
| P5 | docs/09 | 离线发布门禁 `check-p5` + 本说明 |

## 部署入口

- 本地 / Docker：见根目录 README。
- 公网域名 + 已有 nginx：见 `docs/03-部署与配置.md`。
- 本地一行脚本：`deploy.ps1 -Local` / `./deploy.sh --local`（拒绝未验证的 `--public`）。

## 安全边界（发布时仍成立）

- 默认严格透传；Transform 默认关闭且未绑定不进入转换路径。
- 内容安全默认只告警、不自动改响应或禁用 Route。
- 不提交 `.env`、Keyring、`upstreams.tsv`、`docs/02`、样本正文。

## 已知 Deferred（不要当成已上线）

见 docs/05–09 各自 Deferred 节。其中对运维影响最大的是：公网 IP HTTPS 未验证，
因此 README 仍指向 docs/03，而不是「一行公网 IP」替换叙事。
