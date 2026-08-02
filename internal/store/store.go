// Package store 负责 SQLite 持久化：schema 初始化、配置 CRUD、样本落库。
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 驱动，无需 CGO，交叉编译到 Linux 容器不用改工具链
)

//go:embed schema.sql
var schemaFS embed.FS

type Store struct {
	db     *sql.DB
	cipher *Cipher
}

// connPragmas 是必须写在 DSN 里的**连接级** pragma。
//
// 关键点：pragma 的作用域是「连接」，不是「数据库文件」。写在 schema.sql 里
// 只对执行那条 SQL 的连接生效，连接池后来新建的连接一概没有 —— 而
// database/sql 会在连接出错时静默丢弃并重建。
//
// foreign_keys 丢失不会报错，只会让约束变成装饰：指向已删除 ModelName 的
// Route 能插进去，删 ModelName 时 ON DELETE CASCADE 也不再清理它的 Route，
// 于是选路时读到一堆悬挂 Route。选路虽然容忍了悬挂（会跳过），但那是
// 兜底，不该让脏数据先进库。
//
// 对比：journal_mode=WAL 是**库级持久**的，写一次就留在文件头里，
// 所以它留在 schema.sql 里没问题。busy_timeout 同样是连接级，一并放这里。
const connPragmas = "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate"

// Open 打开（或创建）数据库并建表。
func Open(dsn string, c *Cipher) (*Store, error) {
	// _txlock=immediate：写事务一开始就取写锁，避免 SQLite 在事务中途升级锁时
	// 报 SQLITE_BUSY（读事务升级为写事务是死锁的经典来源）。
	db, err := sql.Open("sqlite", dsn+connPragmas)
	if err != nil {
		return nil, fmt.Errorf("打开数据库: %w", err)
	}

	// SQLite 单写者。并发写连接只会撞锁，不会更快，所以限制为 1，
	// 让排队发生在连接池而不是数据库层（前者可控，后者报 BUSY）。
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("连接数据库: %w", err)
	}

	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("读取 schema: %w", err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化 schema: %w", err)
	}

	// schema.sql 只能让**新**库长对：CREATE TABLE IF NOT EXISTS 对已存在的表
	// 是空操作，加不了列。老库的增量变更走 migrate。
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("迁移 schema: %w", err)
	}

	// 收紧文件权限。放在建表之后：WAL 与 shm 是第一次写才出现的，
	// 提前 chmod 会漏掉它们。
	restrictPerms(dsn)

	return &Store{db: db, cipher: c}, nil
}

// dbFilePerm 是库文件应有的权限：**只有属主可读写**。
//
// 这不是「加固」，是把 §3.6.3d 的承诺落实。库里躺着两类东西：
// AES-GCM 加密的上游 key，以及**明文的**样本 —— 完整对话原文、
// 你贴进去的代码、以及请求日志。加密只保护了 key。
const dbFilePerm = 0o600

// restrictPerms 把库文件及其 WAL/shm 副产品收到 0600。
//
// 为什么必须显式做：SQLite 建文件用的是 SQLITE_DEFAULT_FILE_PERMISSIONS
// （0644）再减 umask。默认 umask 022 下结果就是 0644 —— **同机其它用户可读**。
// 而 M7 会把 data/ 挂到宿主机上，那台机器上的任何账号都能拖走全部对话原文。
// 目录建成 0700（main.go）挡不住这一点：挂载点的权限由宿主决定，
// 而且用户完全可能把 RELAY_DB 指到一个共享目录。
//
// 三个文件都要：-wal 里是尚未 checkpoint 的**最新**写入（也就是最近的样本），
// 只收紧主文件等于把最新的那部分留在 0644 上。
//
// 失败一律忽略（这里没有 logger，加一个只为报一句话不值）：权限收不紧是
// 真实的隐患，但它不该让一个本来能用的网关起不来 —— 那会把「数据可能被
// 同机用户读到」升级成「服务完全不可用」。常见的失败恰恰是无害的：
// Windows 上 chmod 语义不同，容器里文件属主可能不是当前进程。
// 真正需要它的是 Linux 部署，而那里它会生效。
func restrictPerms(dsn string) {
	path := dbPathOf(dsn)
	if path == "" || path == ":memory:" {
		return
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err != nil {
			continue // 不存在就跳过：WAL/shm 要等第一次写才出现
		}
		_ = os.Chmod(p, dbFilePerm)
	}
}

// dbPathOf 从 DSN 里取出文件路径。
//
// 当前所有调用方传的都是裸路径（connPragmas 是在 sql.Open 那一行才拼上去的，
// 不经过这里）。剥 query 是防将来：哪天有人把带参数的 DSN 直接传进 Open，
// 少了这一步 Stat 会全部失败，于是 restrictPerms 静默退化成空操作 ——
// 它没有任何输出，谁也不会发现权限其实没收紧。
func dbPathOf(dsn string) string {
	if i := strings.IndexByte(dsn, '?'); i >= 0 {
		return dsn[:i]
	}
	return dsn
}

func (s *Store) Close() error { return s.db.Close() }

// DB 暴露底层连接，供尚未封装的查询使用（样本浏览器等）。
func (s *Store) DB() *sql.DB { return s.db }

func nowMS() int64 { return time.Now().UnixMilli() }
