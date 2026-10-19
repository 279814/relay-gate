# RouteHealth 负状态的持久身份与冷启动恢复

依据 `docs/01` §4.3、§5.2、§9：Tracker 是运行时真相；当前身份的 dead、recovering 和有效 cooldown 跨重启保留，旧 alive 降为 unknown。恢复不能绕 RecoveryGate，客户端取消不形成失败。语义修改必须立即失效，不受缓存 TTL 或旧持久快照影响。

schema 9 扩展既有 `route_health` 快照。Report 保存发送前捕获的配置证明，以及状态机实际使用的当前阈值策略；旧阈值计数不混入新策略。现 Persister 原样复制，不能在落盘时给旧状态补当前 token。证明复用已有 Semantic/Reachability expectation、Recipe 选择事实、生命周期 created_at/语义 counter，不新增配置 cache、进程 epoch 或第二套选路状态。收到合法响应使用 Capability 侧，网络失败使用 Reachability 侧；L1 的子模型仅作为配置 context，不把未使用的 L2 阶段当成其证据。写入及恢复均在 Store 事务内核对当前启用父子关系、绑定、Secret 与相关 policy；SQL 不在 Tracker 锁内。

Transform 的 live 发布指针变化在其既有保存事务内递增受影响 Route 的 capability_revision 并清除持久健康；仅 shadow 变化不改变该语义 counter。这样沿用现有语义身份即可拒绝旧转换配置的健康证明。

其他配置写入也在原事务内按保存的证明核对更新后的当前事实，只清除已经过期的健康；校准成功的 Auth 与 Recipe 联合发布执行相同清理。Route/ModelName/Upstream 语义修改或重新启用会清理本生命周期及无身份旧快照；Endpoint、Recipe、tested Profile、Secret 和阶段策略编辑不清理仍由高层绑定或无关端点证明的状态。旧无身份证据无法判断具体模板依赖时仍保守要求 RecoveryGate；明确的生命周期或健康阈值策略重置才清除此类旧证据。清理失败使配置及其语义版本一起回滚，不新增后台队列或配置缓存。

schema 8 的旧 `route_health` 没有可验证身份。只有明确已不属于当前生命周期的时间/父子关系或停用证据才排除；毫秒相等不证明旧 incarnation。仍可能属于当前 Route 的旧负状态恢复为零计数的 recovering，必须经过 RecoveryGate；不复制旧失败原因、旧计数或猜测不存在的 cooldown，并提供 legacy 来源诊断。恢复出的无身份证据不重新刷写既有持久行，避免已经捕获的 legacy 状态在语义事务清理后迟到复活；取得新证据后才按其发送前身份正常持久化。后续真实或合成的受控恢复按原状态机执行。

验证使用真实 SQLite 冷启动、当前/旧 policy 与 Recipe/Transform/Secret、三类重新启用/删除复用、disabled、相等毫秒、正状态降级和冷却时间；提交前后延迟及 CAS 防止旧快照覆盖新配置。schema 8→9 先配对备份，失败不启动半迁移库；历史 schema 7/8 reader 验证保持只读，schema 9 备份使用新的准确 reader 合同。最后运行相关包、重复目标、构建和静态检查。
