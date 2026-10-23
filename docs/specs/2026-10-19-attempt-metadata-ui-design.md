# 逐 Attempt 元数据展示

沿用 docs/01 §13.2、§16 和既有 schema12 typed DTO。独立前端模块为 RequestLog 的每次尝试提供事实抽屉，为 Sample 列表提供“尝试元数据”入口；样本只请求 GET /samples/{id}/metadata，不读取、解密或复用正文来计算展示。正文入口仍明确进入既有当次密码认证流程。

固定字段展示发送时配置/转换版本、排队与响应头/首字节/首事件/首语义/总耗时、重试策略和风险、请求写入证据、真实 Capability disposition、细 ErrorClass、无正文片段的 hash/结构变化和省略原因、synthetic completion。只投影已知字段，纯文本渲染，不把任意 metadata JSON 或额外响应字段放进页面。Version0 为历史未知；缺失字段、无效时间和未比较内容不猜测为零、成功或“无变化”。

Execution 按 metadata.execution_id 精确打开；execution_stored=false 禁用链接，区分等待持久化、观察未保存和已提交结论下详情不可用，不退回同 Route 相关列表。详情查询返回404时明确保留状态已改变。既有 errors.mjs 的来源逻辑由 metadata lane 维护，本分支不修改。

抽屉请求绑定当前页面对象和请求所有者。关闭、切换样本、登出/重新登录均使旧结果失效；旧 catch/finally 不能恢复数据或改变新请求的忙状态。复用现有弹层锁和 Execution 抽屉，不引入数据缓存、构建链或第二套详情真相。

先用 Node 行为合同验证历史未知、阶段差值、Secret 污点省略、样本安全API、过期响应和精确链接，再接实际模板；最后用真实临时二进制/SQLite与 Playwright 验证 Sample 元数据不触发重认证、正文仍需认证，以及最近错误按钮只打开精确 Execution。Go/DDL12与专用API由原 metadata lane 独占。
