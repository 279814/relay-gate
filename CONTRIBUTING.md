# 贡献指南

欢迎 issue 与 PR。这是个人维护的项目，回应速度取决于我的空闲时间。

## 提 issue

**报 bug** 时请带上：

- relay-gate 版本（`curl -s localhost:18787/healthz` 里的 `version`）
- 部署方式（`docker compose` / 直接跑二进制）与宿主 OS
- 复现步骤，以及你**期望**发生什么

**不要在 issue 里贴**：真实的上游站地址、任何 key、未脱敏的样本内容。
`/admin/api/samples` 的输出里含完整对话原文。

安全问题请走 [SECURITY.md](SECURITY.md)，不要开公开 issue。

## 开发环境

需要 Go 1.26+。不需要 CGO（SQLite 驱动是纯 Go 的）。

```bash
go build ./...
go test ./...
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
go test -race -count=1 ./...            # 竞态
node internal/web/bindings.check.js     # 前端绑定（查 x-model 写向不存在的属性）
node internal/web/app.contract.test.js  # 前端契约
sh scripts/check-entrypoint.sh          # entrypoint 静态不变量
sh scripts/check-deploy.sh              # 部署清单静态不变量
```

改动涉及容器/部署时，`scripts/smoke-m7.ps1` 会在 CI 的 `container` job 里跑。
它需要 Docker 引擎，本地没有也没关系——推上来看 CI 结果。

## 这个项目的一些约定

读代码时会注意到，注释里写的多是**为什么**而不是**做什么**。这不是风格偏好，
而是因为这个项目里很多决定看起来是反直觉的（比如刻意不写 `USER`、
端口刻意只绑 loopback、空白名单刻意全拒），不写下理由的话下一个人会"顺手优化掉"。
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

错误代价不对称时选保守的那一侧：空白名单→全拒、端口→仅 loopback、
库文件→owner-only、缺凭据→拒绝启动。改动这些默认值请说明理由。

## 提交信息

用中文或英文都行，请写清**为什么**改。格式上跟随现有历史
（`fix(m7): ...` / `feat(store): ...`），但不强制。

## License

提交 PR 即表示你同意你的贡献以 [MIT](LICENSE) 授权。
