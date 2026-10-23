# 恢复进程崩溃验证

继续 docs/04 §19/§22 的既定恢复合同。复用生产恢复操作和历史 schema2/schema9 备份夹具，在测试子进程中完成真实文件操作后直接退出，不运行 deferred SQLite 清理。父进程再调用生产 ResumePendingRestore 两次及 Store.Open，验证完整恢复、幂等和业务数据，而非仅检查阶段标记。

schema2 矩阵覆盖 prepared、分别移动 DB/WAL/SHM、isolated、正式数据库 rename、installed、目录同步完成、complete 及 intent 删除。另用 schema9 的真实 Data Key、加密样本和 Keyring 备份，覆盖凭据目录隔离及数据库已安装但凭据尚未安装等七个节点。旧 WAL/SHM 由另一个真实 SQLite 子进程写入后不正常退出产生；旧文件必须按哈希保留在隔离目录，正式路径不得混用旧 sidecar。

不向生产加入环境开关、故障回调或可变全局钩子。测试显式重建生产状态机的可中断文件操作；这证明从这些磁盘状态恢复，不等同于对生产 RestoreDatabase 每行指令实施 kill 注入，也不模拟断电、硬盘缓存丢失或目录 fsync 本身失败。

本次覆盖 17 个进程退出节点；不据此关闭迁移每个 DML/校验/commit/WAL 边界、schema0全部历史变体和CLI全部故障注入的剩余验收。保留这些缺口直到有对应证据。
