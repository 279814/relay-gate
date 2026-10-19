// Package store 负责 SQLite 持久化：schema 初始化、配置 CRUD、样本落库。
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 驱动，无需 CGO，交叉编译到 Linux 容器不用改工具链
)

type Store struct {
	db            *sql.DB
	cipher        *Cipher
	lock          *instanceLock
	path          string
	readerBuildID string
}

// connPragmas 是必须写在 DSN 里的**连接级** pragma。
//
// 关键点：pragma 的作用域是「连接」，不是「数据库文件」。写在建表脚本里
// 只对执行那条 SQL 的连接生效，连接池后来新建的连接一概没有 —— 而
// database/sql 会在连接出错时静默丢弃并重建。
//
// foreign_keys 丢失不会报错，只会让约束变成装饰：指向已删除 ModelName 的
// Route 能插进去，删 ModelName 时 ON DELETE CASCADE 也不再清理它的 Route，
// 于是选路时读到一堆悬挂 Route。选路虽然容忍了悬挂（会跳过），但那是
// 兜底，不该让脏数据先进库。
//
// 对比：journal_mode=WAL 是**库级持久**的，写一次就留在文件头里，
// 所以由迁移完成后统一设置即可。busy_timeout 同样是连接级，一并放这里。
const connPragmas = "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate"

// InstanceLock 是 Open 持有的同一把按数据库路径的独占 OS 锁。
// 启动时 data/secrets 的写入必须先于 Open，却要与 SQLite 受同一把锁保护：
// 先 AcquireInstanceLock，写完 secrets 再交给 OpenLocked。
type InstanceLock struct {
	lock *instanceLock
	path string
}

// AcquireInstanceLock 取得 dsn 对应数据库的实例锁；已被持有时返回 ErrInstanceLocked。
func AcquireInstanceLock(dsn string) (*InstanceLock, error) {
	path := dbPathOf(dsn)
	lock, err := acquireInstanceLock(path)
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnsafeLockPath, err)
	}
	return &InstanceLock{lock: lock, path: absolute}, nil
}

// Close 释放尚未移交给 Store 的锁；移交后为 no-op，可无条件 defer。
func (l *InstanceLock) Close() error {
	if l == nil || l.lock == nil {
		return nil
	}
	lock := l.lock
	l.lock = nil
	return lock.Close()
}

// Open 打开（或创建）数据库并建表。
func Open(dsn string, c *Cipher) (*Store, error) {
	if c == nil {
		return nil, ErrNoKey
	}
	lock, err := acquireInstanceLock(dbPathOf(dsn))
	if err != nil {
		return nil, err
	}
	st, err := openLocked(dsn, c, lock, "")
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	return st, nil
}

// OpenLocked 与 Open 相同，但使用调用方已持有的同路径实例锁。
// 成功时锁归 Store 所有（随 Store.Close 释放）；失败时仍归调用方。
func OpenLocked(dsn string, c *Cipher, held *InstanceLock) (*Store, error) {
	return openWithHeldLock(dsn, c, held, "")
}

func openWithHeldLock(dsn string, c *Cipher, held *InstanceLock, readerBuildID string) (*Store, error) {
	if c == nil {
		return nil, ErrNoKey
	}
	if held == nil || held.lock == nil {
		return nil, fmt.Errorf("%w: 未持有实例锁", ErrUnsafeLockPath)
	}
	absolute, err := filepath.Abs(dbPathOf(dsn))
	if err != nil || !sameFilesystemPath(absolute, held.path) {
		return nil, fmt.Errorf("%w: 实例锁与数据库路径不一致", ErrUnsafeLockPath)
	}
	st, err := openLocked(dsn, c, held.lock, readerBuildID)
	if err != nil {
		return nil, err
	}
	held.lock = nil
	return st, nil
}

func openLocked(dsn string, c *Cipher, lock *instanceLock, readerBuildID string) (*Store, error) {
	databasePath := dbPathOf(dsn)

	// Resume crash-interrupted restore before treating a missing/partial DB as empty.
	if err := resumeIncompleteRestoreIfAny(context.Background(), databasePath, c); err != nil {
		return nil, err
	}

	// _txlock=immediate：写事务一开始就取写锁，避免 SQLite 在事务中途升级锁时
	// 报 SQLITE_BUSY（读事务升级为写事务是死锁的经典来源）。
	db, err := sql.Open("sqlite", dsn+connPragmas)
	if err != nil {
		return nil, fmt.Errorf("打开数据库: %w", err)
	}

	// Migration 在线备份需要一条持有 BEGIN IMMEDIATE 的连接和另一条只读
	// source 连接。完成 migration 后再收紧为单写连接。
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("连接数据库: %w", err)
	}

	if err := migrateToDevelopmentSchema(context.Background(), db, databasePath, c, defaultMigrationBackupIdentity(), readerBuildID); err != nil {
		db.Close()
		return nil, fmt.Errorf("迁移 schema: %w", err)
	}
	var journalMode string
	if err := db.QueryRow(`PRAGMA journal_mode=WAL`).Scan(&journalMode); err != nil {
		db.Close()
		return nil, fmt.Errorf("启用 WAL: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		db.Close()
		return nil, fmt.Errorf("启用 WAL: SQLite 返回 %q", journalMode)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// 收紧文件权限。放在建表之后：WAL 与 shm 是第一次写才出现的，
	// 提前 chmod 会漏掉它们。
	restrictPerms(dsn)

	st := &Store{db: db, cipher: c, lock: lock, path: databasePath, readerBuildID: readerBuildID}
	keys, err := readDataKeys(context.Background(), db, c)
	if err != nil {
		db.Close()
		return nil, err
	}
	c.installDataKeys(keys)
	if err := st.ValidateEncryptedState(); err != nil {
		db.Close()
		return nil, fmt.Errorf("启动密文全量校验: %w", err)
	}
	if err := repairLegacyAuthSecretBindings(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化 Auth Secret 绑定元数据: %w", err)
	}
	if err := ensureProbeRetentionIndexes(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化探活保留索引: %w", err)
	}
	if err := initializeCurrentSettings(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化分阶段设置: %w", err)
	}
	if err := st.interruptPendingAuditEvents(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("标记未完成审计: %w", err)
	}
	return st, nil
}

func (s *Store) DatabasePath() string { return s.path }

// ActivateMaster switches the live Cipher after Keyring key_activated (§12.7).
// Direct secrets and Data Key wrappers follow the new master; sample/security
// body keys and ciphertext remain unchanged. Retired masters are retained only
// until full verification and ForgetRetiredMasterKeys finish the rotation.
func (s *Store) ActivateMaster(passphrase string) error {
	if s == nil || s.cipher == nil {
		return ErrNoKey
	}
	return s.cipher.ActivateMaster(passphrase)
}

// ForgetRetiredMasterKeys is called only after full verification and keyring
// cleanup. Independent Data Keys continue to open all sample/evidence bodies.
func (s *Store) ForgetRetiredMasterKeys() {
	if s == nil || s.cipher == nil {
		return
	}
	s.cipher.mu.Lock()
	defer s.cipher.mu.Unlock()
	for i := range s.cipher.previous {
		s.cipher.previous[i] = retiredMaster{}
	}
	s.cipher.previous = nil
}

func defaultMigrationBackupIdentity() MigrationBackupIdentity {
	return MigrationBackupIdentity{
		PairedBuildID:  "relay-gate-pre-p0",
		ReaderContract: "schema-1-reader",
	}
}

func migrateToDevelopmentSchema(ctx context.Context, db *sql.DB, databasePath string, cipher *Cipher, identity MigrationBackupIdentity, readerBuildID string) error {
	for {
		state, err := inspectSchemaState(ctx, db)
		if err != nil {
			return err
		}
		switch {
		case state.Empty:
			return initializeEmptySchemaFourteen(ctx, db, cipher)
		case state.Version == 0 && state.Variant != "":
			if _, err := normalizeLegacyToSchemaOne(ctx, db, databasePath, cipher, identity); err != nil {
				return err
			}
		case state.Version == 1:
			if _, err := migrateSchemaOneToTwo(ctx, db, databasePath, cipher, identity); err != nil {
				return err
			}
		case state.Version == 2:
			if _, err := migrateSchemaTwoToThree(ctx, db, databasePath, cipher, identity); err != nil {
				return err
			}
		case state.Version == 3:
			if _, err := migrateSchemaThreeToFour(ctx, db, databasePath, cipher, identity); err != nil {
				return err
			}
		case state.Version == 4:
			if _, err := migrateSchemaFourToFive(ctx, db, databasePath, cipher, identity); err != nil {
				return err
			}
		case state.Version == 5:
			if _, err := migrateSchemaFiveToSix(ctx, db, databasePath, cipher, identity); err != nil {
				return err
			}
		case state.Version == 6:
			if _, err := migrateSchemaSixToSeven(ctx, db, databasePath, cipher, identity); err != nil {
				return err
			}
		case state.Version == 7:
			if _, err := migrateSchemaSevenToEight(ctx, db, databasePath, cipher, identity); err != nil {
				return err
			}
		case state.Version == 8:
			if _, err := migrateSchemaEightToNine(ctx, db, databasePath, cipher, identity, readerBuildID); err != nil {
				return err
			}
		case state.Version == 9:
			if _, err := migrateSchemaNineToTen(ctx, db, databasePath, cipher, identity, readerBuildID); err != nil {
				return err
			}
		case state.Version == 10:
			if _, err := migrateSchemaTenToEleven(ctx, db, databasePath, cipher, identity, readerBuildID); err != nil {
				return err
			}
		case state.Version == 11:
			if _, err := migrateSchemaElevenToTwelve(ctx, db, databasePath, cipher, identity, readerBuildID); err != nil {
				return err
			}
		case state.Version == 12:
			if _, err := migrateSchemaTwelveToThirteen(ctx, db, databasePath, cipher, identity, readerBuildID); err != nil {
				return err
			}
		case state.Version == 13:
			if _, err := migrateSchemaThirteenToFourteen(ctx, db, databasePath, cipher, identity, readerBuildID); err != nil {
				return err
			}
		case state.Version == developmentSchemaVersion:
			return nil
		default:
			return fmt.Errorf("%w: 无迁移路径 %+v", ErrUnknownSchema, state)
		}
	}
}

// dbFilePerm 是库文件应有的权限：**只有属主可读写**。
//
// 这不是「加固」，是把 §3.6.3d 的承诺落实。库里躺着两类东西：
// 上游 Key、Data Key 包装、加密的样本正文，以及仍敏感的路径/头/请求日志元数据。
// 正文加密不能替代对整个数据库及其 WAL/SHM 的权限保护。
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

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return errors.Join(s.db.Close(), s.lock.Close())
}

// DB 暴露底层连接，供尚未封装的查询使用（样本浏览器等）。
func (s *Store) DB() *sql.DB { return s.db }

func nowMS() int64 { return time.Now().UnixMilli() }
