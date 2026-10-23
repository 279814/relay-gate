# 恢复进程崩溃验证

继续 docs/04 §19/§22 的既定恢复合同。复用生产恢复操作和历史 schema2/schema9 备份夹具，在测试子进程中完成真实文件操作后直接退出，不运行 deferred SQLite 清理。父进程再调用生产 ResumePendingRestore 两次及 Store.Open，验证完整恢复、幂等和业务数据，而非仅检查阶段标记。

schema2 矩阵覆盖 prepared、分别移动 DB/WAL/SHM、isolated、正式数据库 rename、installed、目录同步完成、complete 及 intent 删除。另用 schema9 的真实 Data Key、加密样本和 Keyring 备份，覆盖凭据目录隔离及数据库已安装但凭据尚未安装等七个节点。旧 WAL/SHM 由另一个真实 SQLite 子进程写入后不正常退出产生；旧文件必须按哈希保留在隔离目录，正式路径不得混用旧 sidecar。

不向生产加入环境开关、故障回调或可变全局钩子。测试显式重建生产状态机的可中断文件操作；这证明从这些磁盘状态恢复，不等同于对生产 RestoreDatabase 每行指令实施 kill 注入，也不模拟断电、硬盘缓存丢失或目录 fsync 本身失败。

本次覆盖 17 个进程退出节点；不据此关闭迁移每个 DML/校验/commit/WAL 边界、schema0全部历史变体和CLI全部故障注入的剩余验收。保留这些缺口直到有对应证据。

另补 schema1→2 Backfill 的逐 DML 失败验证：通过现有执行器接口包装真实 SQL 事务，在第 N 条写入实际执行后返回固定错误，覆盖基准URL/完整URL和三种模型协议。发现并逐个验证 34 条 DML，确保扩展 DDL、全部此前写入及密文在回滚后保持原 source fingerprint；随后生产 Store.Open 可完整重新迁移。这里只验证 Backfill 组件的写后错误与回滚，不把测试包装器当成生产完整迁移链的崩溃注入。

另补生产 `migrateSchemaOneToTwo` 的真实 SQLite 容量失败：依据同一合成来源成功迁移的95页，分别将新建测试数据库的 `max_page_count` 限为28、61、94页，三次均验证驱动返回类型化 `SQLITE_FULL`。不是把宿主磁盘写满，也不向生产加错误开关。失败后完整 source fingerprint、原密文和 integrity_check 保持，预先发布的备份通过生产 CheckBackup；关闭数据库后用生产 Open 无修补地迁移至 schema17，并核对旧备份 hash 未被重试覆盖。`TestMigrationStorageFullKeepsSourceAndBackupRecoverable` 三个容量边界实跑通过。该结果只覆盖这些实际容量错误，不代替每条 DML、commit/WAL/fsync 的完整错误矩阵。

另以每个测试数据库独有的 `database/sql.Connector` 包装真实 modernc 连接，直接调用生产 `migrateSchemaOneToTwo`，不替换全局 sqlite driver，不改变生产入口或增加故障开关。基准URL/完整URL、三协议夹具共测得48个应用侧驱动边界：38次成功Exec后返回错误、10次Query成功打开游标后关闭并返回错误；备份仍转发真实NewBackup句柄。逐点失败后关闭连接，以普通注册driver重开物理文件，核对结构、完整性、密文、8个Endpoint、生产备份验证及重试不覆盖旧备份。提交前失败保持完整schema1；实际COMMIT已完成但调用报错时允许完整schema2，不能伪称已回滚。首段、中段、提交后三个代表状态另经正常Store.Open到schema17。见[48边界运行记录](../evidence/migration-runner-driver-boundaries-20261023.json)。

这48个位置是应用侧真实驱动调用，不等于SQLite内部每条指令：冻结DDL脚本仍由一次Exec执行，Query故障发生在游标已打开但结果未消费时。此记录不涵盖其他迁移版本/历史来源、内部逐DDL切点、物理commit/WAL/fsync故障或断电，完整P0故障矩阵仍保留未关闭范围。
