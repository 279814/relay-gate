# 贡献指南

欢迎 issue 与 PR。这是个人维护的项目，回应速度取决于我的空闲时间。

修改前先读[需求基线](docs/01-需求与设计.md)与当前[交接记录](docs/10-维护与交接.md)；历史阶段记录见 docs/04–09。默认安装为 HTTP `IP:port`，Linux 另有独立[公网 IP HTTPS 入口](docs/13-公网IP-HTTPS.md)；实现入口不代表真实公网签发已验收。生产探活经 `probe.Executor` 与 `SyntheticCoordinator`；RunState 走 `runstate.Controller`。

## 提 issue

**报 bug** 时请带上：

- relay-gate 版本（`curl -s localhost:18787/healthz` 里的 `version`）
- 部署方式（`docker compose` / 直接跑二进制）与宿主 OS
- 复现步骤，以及你**期望**发生什么

**不要在 issue 里贴**：真实的上游站地址、任何 key、未脱敏的样本内容。
样本详情经再次验证口令后可返回完整对话原文，不要粘贴其输出。

安全问题请走 [SECURITY.md](SECURITY.md)，不要开公开 issue。

## 开发环境

需要 `go.mod` 指定的 Go 版本（当前 1.27.3）。不需要 CGO（SQLite 驱动是纯 Go 的）；Linux CI 的竞态检测需要 CGO。

```bash
go build ./...
go test -timeout=20m -count=1 ./...
go vet ./...
gofmt -l .          # 应该没有输出
```

前端是单页 HTML + Alpine.js，`go:embed` 打进二进制，没有构建链。
改完 `internal/web/static/` 直接 `go build`。

## 提 PR 前

CI 会跑这些，本地先过一遍能省一个来回：

```bash
gofmt -l .                              # 格式
go vet ./...                            # 静态检查
go test -race -timeout=20m -count=1 ./... # 竞态，含真实大数据保留 fixture
node internal/web/bindings.check.js     # 前端绑定（查 x-model 写向不存在的属性）
node internal/web/app.contract.test.js  # 前端契约
node internal/web/configadmin.contract.test.js
node internal/web/manual-probe.contract.test.js
node --test internal/web/settings.contract.test.mjs internal/web/state.contract.test.mjs internal/web/recipe_admin.contract.test.mjs internal/web/privacy.contract.test.mjs internal/web/endpoint.contract.test.mjs
node --test internal/web/modules.contract.test.mjs  # 前端业务模块契约
python scripts/deploy.contract.test.py  # 安装脚本行为（假 Docker，临时目录）
python scripts/deploy-public.contract.test.py # 公网安装器离线行为，不申请公网证书
bash scripts/check-p0.sh                # 探活离线门禁
bash scripts/check-p5.sh                # 发布与私有文件门禁
sh scripts/check-entrypoint.sh          # entrypoint 静态不变量
sh scripts/check-deploy.sh              # 部署清单静态不变量
```

部署行为测试需要 Bash、Python 3 与 PowerShell 7（`pwsh`）；Linux 与 Windows CI 都会运行。Windows 未启用 CGO 时用 `go test -timeout=20m -count=1 ./...`，将 `-race` 留给 Linux CI。

改动涉及容器/部署时，`scripts/smoke-m7.ps1` 会在 CI 的 `container` job 里跑。
它需要 Docker 引擎，本地没有也没关系——推上来看 CI 结果。

`public-edge` CI 使用真实 Nginx 与本地 CA 验证 TLS、原字节流、续期故障和过期关门，不向公共 CA 申请证书。真实公网签发、最终目标提交的长流及 48 小时持续运行，须按[验收说明](docs/15-实际时长验收.md)另留记录；短时门禁、开发版本或本地 CA 结果不能替代它们。

管理 API 测试须由调用方固定 `expected_revision`，不要在共享 HTTP helper 中自动读取最新版本。Settings 的部分更新只提交当前字段，RunState 使用独立版本；旧版本应 409，缺少有效版本应 400，已提交但激活／drain 待完成应保留 503 的 `persisted=true` 元数据。前端回归应覆盖草稿保留、显式重载、登出清理和迟到响应隔离；Endpoint 表单还要覆盖其受限字段与提交后的激活失败。

## 这个项目的一些约定

读代码时会注意到，注释里写的多是**为什么**而不是**做什么**。这不是风格偏好，
而是因为这个项目里很多决定需要保留背景（比如 Dockerfile 刻意不写 `USER`，
由 entrypoint 修正数据目录权限后降权；默认发布所有接口以支持 HTTP `IP:port`），不写下理由的话下一个人会"顺手优化掉"。
如果你的 PR 做了一个非显然的选择，请在注释里留下理由。

### 新增检查器请做变异验证

这个项目吃过几次亏：检查器存在、注释写着它能查某个问题、但实际查不到，
于是屏幕上打印 `[PASS]` 而 bug 照样进主干。所以新增静态检查时，请：

1. 人为把目标缺陷放回去，确认检查**变红**
2. 还原正确实现，确认**变绿**

两个方向都要验。只验第二个方向的检查器，等于没有检查器。

### 静默失败优先

这个项目最在意的一类 bug 是**不报错、不崩、只是给出一个错答案**的那种：
UI 绑定写错但 Alpine 静默创建属性、统计因日志丢行而偏低、
chown 循环因变量未赋值而变成空操作。如果你发现一处，即使很小，也值得单独提。

### 保守默认

错误代价不对称时选保守的那一侧：库文件→owner-only、无法读取凭据→拒绝启动、
观察不完整→不声称 supported。当前安装默认监听所有接口且没有登录 IP 白名单；
修改这些已文档化的默认行为时，请同时更新部署说明与验证。

## 提交信息

用中文或英文都行，请写清**为什么**改。格式上跟随现有历史
（`fix(m7): ...` / `feat(store): ...`），但不强制。

## License

提交 PR 即表示你同意你的贡献以 [MIT](LICENSE) 授权。
