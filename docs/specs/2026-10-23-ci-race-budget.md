# CI 迁移回归的执行预算

2026-10-23，三个功能分支的完整 `-race` 回归均在 Store 测试包累计运行 1200 秒后触发 Go 的包级超时：

- [Canary：39916824484](https://github.com/279814/relay-gate/actions/runs/39916824484/job/120292080623)，当时执行 `TestModelNameDeleteDoesNotCascadeExternalRoutes`，已运行 0 秒。
- [上游样本：39916877369](https://github.com/279814/relay-gate/actions/runs/39916877369/job/120292238580)，当时执行 `TestSchemaTenRotationBackupPinsReaderAndRestoresMetadata`，已运行 1 秒。
- [Transform：39916903613](https://github.com/279814/relay-gate/actions/runs/39916903613/job/120292318349)，当时执行 `TestSecurityMigrationBackupFailureStopsBeforeDDL`，已运行 1 秒。

这些日志说明整包预算已用尽，不能据此把最后被中断的短用例认定为死锁。新增迁移场景逐次启动真实 SQLite、备份与校验；pure-Go SQLite 在竞态检测下的累计开销需要由完整重跑确认。

本次把完整竞态回归的包级上限从 20 分钟调整为 30 分钟，包含构建、重复普通回归及其他检查的 test job 上限从 40 分钟调整为 55 分钟。保留全部测试、竞态检测、50k/200k 真实保留量及清理本身的 2 秒断言；不修改生产代码。新预算是否足够以各功能分支的新 CI 结果为准，不能将修改工作流本身当作验收通过。

同一 PR 的新提交自动取消旧提交的 CI，避免已被替代的构建占用队列。并发组使用工作流名及 PR 编号；非 PR 运行使用唯一 run ID，保证不同 PR 以及主分支的不同推送互不取消。语义依据 [GitHub Actions 官方并发控制说明](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)。11 项检查保持不变。
