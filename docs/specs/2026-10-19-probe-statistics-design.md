# Probe 历史统计执行设计

本轮补齐 `docs/01` §16.2 的只读聚合和界面，基于冻结 schema 12 `23b8d22`。只查询既有历史事实，不增加表、索引、持久化 JSON 或迁移，不读取正文、认证值、Recipe 当前绑定或当前 Route 配置。

## 两种事实视图

新增 `GET /admin/api/probe-statistics`，`basis=executions|daily`。两种视图都按 UTC 日、Route/Upstream scope、Endpoint、Trigger、Origin 分组；执行视图另按执行记录内的 db Recipe/版本 ID、profile ID/revision、embedded template ID/revision 分组。不同 builtin 和版本始终区分，`legacy_migration` 明确标记。`real_traffic_context` 只表示真实流量的捕获上下文，不生成 Recipe 成功率或 Probe 成本。

执行视图统计保存的执行数、实际发送数、`/models`/模型 L2 次数、成功/失败/取消或忽略/观察不完整、发送前结果、首语义后预期取消及已记录 Token。成功率分母为成功+失败；取消/忽略和观察不完整不进入分母。已成功或首语义后的 ExpectedCancel 成功不计为失败。分母为零时成功率为 unknown。发送前失败保留在执行结果中，但不会增加真实发送次数。

daily 视图读取持久化账本的请求、成功/失败/取消、Token 和 piggyback 节省计数，保留 730 日水位。它没有 Recipe identity，不生成虚假 Recipe 率；执行保留清理后的历史成本仍可查看。

## 已确认的历史限制

- 历史 Trigger 只有 scheduled/manual/calibration/recovery/real_traffic，旧 Canary 来源无法恢复，保持 unavailable，不按时间、Route 或 template 名字猜测。schema14 的新增事实和独立 `basis=canary` 视图见 [Canary 设计](2026-10-19-canary-design.md)；已明确记录的 Canary 从 Recipe 执行分母排除。
- Token 列为 NOT NULL DEFAULT 0，缺少 presence 位。非零值是已记录值，零值按 unknown 展示；执行视图另外显示未知覆盖数，daily 明示无法恢复逐次覆盖。数值不是计费账单。
- daily 的 piggyback counter 无 Recipe identity，不能分摊给 Recipe/版本；Recipe 视图对应值为 unknown。
- 执行统计仅覆盖仍保留记录；保留政策和筛选结果的最早/最晚日期均可见，不宣称窗口内完整历史。

## 边界与分页

typed 白名单筛选支持 UTC 时间、scope/ID、Recipe/版本/存储身份、Endpoint、Trigger、Origin；不支持的 daily Recipe 筛选明确拒绝。默认近 7 日，执行窗口跨度最多 92 日，daily 最多 730 日；每页默认 50、最多 200，SQL 有 2 秒 context 预算。

每次请求以同一只读事务读取总分组数、保留信息和当前页。执行翻页固定首页的已提交行/观察顺序上界，cursor 绑定筛选和排序键；并发新插入不会改变该次翻页的执行分母。保留删除可能让后续页减少，界面明确提示。daily 跨页计数为每次请求的实时已提交快照，可增长；不伪装无法恢复的历史冻结值。group keyset 支持下一页、上一页和首页；客户端只保留当前一页，不自动拉取全量。

所有接口使用既有管理员权限和 no-store。响应只含 typed 计数与身份元数据。UI 沿用现有成本/探测风格，纯文本渲染，筛选及会话变化使旧响应失效，unknown 保持可见。

## 验证

先红后绿覆盖多 Recipe/版本/builtin、来源、ExpectedCancel、无发送/不完整/取消、空分母、零 Token、保留水位、UTC 边界、cursor 筛选绑定、双向翻页、并发插入及同事务总数/页。HTTP 验证鉴权、白名单、限制和 no-store；Node 验证真实 API 路径、翻页、筛选及旧响应隔离；浏览器只使用临时数据和 loopback。最后运行相关完整包、build/vet 和前端门禁，提交 draft PR 由父整合审阅。

实测使用临时 SQLite 和合成身份：归档 Recipe 的两个版本不随当前发布指针变化；首页后新增执行不进入原 cursor 的分母；并发保留删除时每次响应的总数和页仍使用同一事务。HTTP 从未注册路由的 404 变为鉴权后的 typed 200；Node 从缺失入口变绿，并单独复现和修复输入已编辑但 change 事件尚未触发时的旧响应覆盖。

真实浏览器运行临时 loopback binary：55 个分组按 50→5→50 翻页，精确身份筛选为 1 行；daily 显示已保存的 piggyback=4、output unknown 和无 Recipe 身份。附加 HTML 外观的合成身份保持纯文本，没有生成 img 元素或执行事件。该轮没有调用线上模型、读取私有输入或改变运行时长。

基线 schema 12 的发布和 binary 自检仍断言旧 schema 11，本轮仅把这两个当前版本断言更新到 12，没有修改迁移或历史 fixture。自检保留单一 SQL 聚合实现，复用既有 cursor、权限、前端工厂和页面样式，没有客户端全量收集或新增统计持久层。
