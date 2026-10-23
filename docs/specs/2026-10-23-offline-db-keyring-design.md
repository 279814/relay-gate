# 离线数据库命令的目标 Keyring 合同

依据 docs01 §19.4/§23 和 README 的 `db check-backup/restore --database` 命令，最终只读发布审查确认旧实现误用 `config.Load()`：自定义目标路径未选择其 Keyring，且离线检查被无关 Admin/Relay 缺失阻断。沿用原离线命令和 Keyring，不增加配置来源、缓存或数据库结构。

选择顺序保持显式性：`--use-backup-keyring` 完整沿用已有校验过的归档选择；否则非空 `ENCRYPTION_KEY` 优先；未设置时只读指定数据库父目录中的当前稳定 Keyring。Keyring 复用现有文件解析器，以一次文档快照校验 format1、有效 active/keyID、idle/cleaned 状态和无 pending；不以 Status+LoadActive 两次读取拼接可能变化的状态。只读操作不恢复 previous、不推进轮换、不写源目录。错误 Master 由原 CheckBackup 的 cipher/密文配对验证拒绝，不回退其它来源。

真实命令级子进程在去除服务凭据、改变 cwd 与错误 RELAY_DB 的环境下验证检查与恢复；相异 cwd/target Master、正确/错误显式覆盖、未完成/未知 Keyring、缺损当前但合法 previous 等均使用临时目录。检查/拒绝前后逐文件哈希保证源数据库、当前/previous Keyring 和备份未改。已有归档 Keyring、ReaderContract、授权和主命令分派合同保持；完整 cmd/keyring/config 回归与 vet 验证影响范围。
