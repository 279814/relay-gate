# Settings 最终合同

依据 `docs/01` §7.4、`docs/04` §P0-14/17 实施。运行时 `model.Settings`、HTTP DTO、页面仅保留分阶段预算。真实请求首语义下限 300 秒，real/L1/L2/count_tokens 的 connect 均不得超过 total；预算构造不再读取旧别名。各用途 policy/fingerprint 继续使用同一份已发布 Settings，不新增 schema、cache 或 epoch。

`configadmin.SettingsService` 实现 API 的 `SettingsAdmin`，负责校验和 Store CAS。启动时在既有 setting 表中一次性规范化受控旧 JSON；缺省 Settings 初始化为 revision 1。正常 Get、bundle、事务内 current 查询使用严格新格式，旧字段仅留在启动和历史迁移 decoder，历史备份读取/校验不得改写备份。原有不可用历史数值的安全读侧处理保持一致，不以别名回退代替当前预算。

GET `/admin/api/settings` 返回 `{settings,revision,limits}`。PUT 接受 flat partial 新字段与必填正整数 `expected_revision`，以同代读值补足未指定字段，并使用客户端持有的 revision 保存；缺失/非法 revision 和 legacy/unknown 字段 400，旧 revision 409，失败不发布。提交成功后使用现有 ConfigPublisher；刷新失败返回 503 `config_activation_pending,persisted=true,new_revision`，明确保存已发生。RunState revision 独立。

设置模块沿统一 `api.mjs` 出口，展示全部新 stage。草稿与其 revision 一起保存；409、提交后激活待完成都保留草稿并禁止自动重试，用户显式重新加载后才能继续。无关页面刷新不得覆盖未保存草稿。测试客户端、运维脚本显式传入先前取得的 revision，不通过通用写 helper 偷读最新 revision。

验证顺序为新 HTTP/模型/预算/启动兼容红灯，最小实现，迁移实际 fixture 和脚本，再运行 Go、Node 与真实浏览器保存/冲突/待激活流程。仅使用临时数据库与回环 HTTP，不接触用户数据。
