# Recipe 与 ClientProfile 管理

管理台「配方」提供手工草稿、不可变版本、脱敏差异预览、单次真实测试、发布、Force、停用与归档。「客户端形状」提供安全学习候选的分页筛选、详情、预览、测试后启用与停用；不提供直接写入任意用户正文的 Profile 创建入口。

Recipe 编辑后点击「保存新版本」才持久化。预览、测试和发布针对选中的已保存版本；未保存编辑会清空测试依据并禁用这些动作。页面重新打开时从 Recipe 和版本 API 恢复 draft/published 指针及全部版本，不依赖浏览器持久存储。并发 409 保留当前编辑内容，要求明确重新载入后再提交。

模型端点必须提供该站且协议一致的 Route。Route 作用域自动固定 RouteID；Upstream 作用域需明确输入 RouteID。`models` Recipe 绑定 Upstream。预览只使用已经发布的不含凭据的 ProbeSnapshot、模板编译器和共享出站 URL/Auth 规则，不加载 API Key 或解析 Probe Secret，也不触发含凭据的 TTL 快照刷新。旧 `legacy_exact` Endpoint 须先审核转换，不能通过解密原 URL 实现预览。

预览的 Secret 均为固定 marker，时间/会话值也固定。它返回脱敏 URL、headers、body、相对当前解析模板的差异字段、占位符列表，以及带域和格式版本的 `redacted_template_hash`。该摘要覆盖脱敏 method/URL/headers/body；`redacted_template_body_bytes` 仅计脱敏正文。它们均不是实际出站正文的大小或证据摘要。Secret 值、长度或 revision 变化不影响同一模板的预览结果。

成本展示为估算区间，输出上限读取 `ProbeRequestOutputTokenLimit` 支持的实际声明字段。正文包含任意长度 Secret 时，不能在不泄漏长度的前提下证明有限输入上界，因此返回 `input_bound_known=false`。没有可证明的输出限制时返回 `output_bound_known=false`。页面明确显示未知上界，不将其显示为零成本；所有真实测试都要求用户确认可能产生 token 费用。

测试通过生产 Executor 与统一出站、分类器、合成准入、全局 observation sequencer 和 ResultRecorder 恰好发送一次；暂停时零发送并返回 503。Recipe 测试不隐式发布，显式测试不改正在服务的 Capability。发布必须引用同一 RecipeVersion/target 的完整、已发送、已完成且 DB-current 的测试证据。成功测试只能正常发布；失败测试需 `force=true`，页面还要求勾选明确确认并再次确认操作。Force 不跳过配置、Secret、revision、身份或取消状态门禁。

ClientProfile 读取会重新 sanitizer，原始业务正文、认证头与认证 query 不回显。候选测试固定 ID/revision/status，使用 `BindingExplicitProfileTest`。失败保留 candidate；成功后在同一 Store 事务重验 DB-current token 和候选状态，再切换为同站同端点唯一 tested fallback，旧 tested 降为 disabled。已 disabled 的 Profile 不能直接重新启用，须使用新候选重新测试。Profile 优先级仍低于 Route/Upstream 已发布 Recipe。

所有相关持久写入提交后先使 ProbeSnapshot 不可用，再失效旧语义状态并刷新统一配置。刷新失败返回 `503 code=config_activation_pending,persisted=true,id,new_revision`，数据库写入仍然保留；不能重放旧 revision 冒充回滚。页面明确提示刷新查看。停用与归档保留历史测试，不做硬删除。

API 均位于 `/admin/api` 并受现有管理鉴权/同源保护：

| 路径 | 行为 |
| --- | --- |
| `GET/POST /probe-recipes` | 分页筛选 / 创建 draft |
| `GET /probe-recipes/{id}` | 状态、revision 和版本指针 |
| `GET/POST /probe-recipes/{id}/versions` | 分页版本 / 新增 manual 不可变版本 |
| `GET /probe-recipe-versions/{id}` | 按不可变版本ID读取 |
| `POST /probe-recipe-versions/{id}/preview` | 脱敏差异和成本估算 |
| `POST /probe-recipe-versions/{id}/test` | 单次显式测试，要求 expected_revision |
| `POST /probe-recipes/{recipe_id}/versions/{version_id}/publish` | 校验父子关系后独立发布，要求 expected_revision、test_execution_id；失败需 force |
| `POST /probe-recipes/{id}/disable`、`/archive` | 带 expected_revision 停用 / 归档 |
| `GET /client-probe-profiles`、`/{id}` | 分页筛选 / 安全详情 |
| `POST /client-probe-profiles/{id}/preview` | 候选脱敏差异与成本 |
| `POST /client-probe-profiles/{id}/test` | 单次测试成功后原子启用，要求 expected_revision |
| `POST /client-probe-profiles/{id}/disable` | 带 expected_revision 停用 |

版本写入仅接受 method、fixed_raw_query、有序 headers/values、互斥 body_text/body_base64、stream_expected、timeout_profile 和 expected_revision；不能伪造 source/origin。未知字段、尾随 JSON、坏 Base64、跨父版本和旧 revision 会失败。Recipe、版本及 Profile 列表使用服务端 SQL 过滤和绑定资源/筛选的 cursor；坏格式、跨资源、改变筛选复用 cursor 或非法 limit 返回 400。

验证包括真实 HTTP/Store/Executor 的成功发布、实际失败后 Force、Profile 成功启用/失败保留/禁用、暂停零发送、配置激活待完成、DTO/凭据/分页回归，以及前端冲突保留、Force 授权、样本安全草稿入口和登出清理契约。

可复验真实浏览器夹具（只使用临时 SQLite、loopback 模拟上游和合成管理口令；不会启动真实业务或访问公网）：

```powershell
$env:RELAY_RECIPE_BROWSER_FIXTURE='1'
$env:RELAY_RECIPE_BROWSER_DONE_FILE=Join-Path $env:TEMP ('relay-recipe-browser-' + [guid]::NewGuid().ToString('N'))
go test ./internal/api -run '^TestRecipeAdminBrowserFixture$' -count=1 -v -timeout=20m
```

使用打印的临时 URL 和 fixture 口令登录。依次执行：保存 v2 → 预览 → 确认单次测试 → 发布；再到客户端形状页以打印的 RouteID 预览、测试启用、禁用。测试失败与 Force 路径可在手工版本中加入有序头 `[{"name":"X-Fixture-Outcome","values":["reject"]}]`，夹具将返回真实 HTTP 400；普通发布应禁用，明确勾选后 Force 才可提交。该头仅控制测试夹具，与生产逻辑无关。完成后在另一个终端创建 `RELAY_RECIPE_BROWSER_DONE_FILE` 指定文件让夹具退出；15 分钟未完成会失败退出。

2026-10-18 的 Windows Chromium 实际操作已验证正常 Recipe 发布、Profile tested→disabled，以及失败测试授权流程。浏览器截图和快照留在本机 ignored 的 `output/playwright/`，不提交认证态或页面数据。全仓 Go test、build、vet 与 Node/绑定门禁已执行；Linux race 验证仍由 CI 提供。此交付不将其它未完成需求或真实公网/长时验证标记完成。
