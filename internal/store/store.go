// Package store 负责 SQLite 持久化：schema 初始化、配置 CRUD、样本落库。
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 驱动，无需 CGO，交叉编译到 Linux 容器不用改工具链
)

//go:embed schema.sql
var schemaFS embed.FS

type Store struct {
	db     *sql.DB
	cipher *Cipher
}

// Open 打开（或创建）数据库并建表。
func Open(dsn string, c *Cipher) (*Store, error) {
	// _txlock=immediate：写事务一开始就取写锁，避免 SQLite 在事务中途升级锁时
	// 报 SQLITE_BUSY（读事务升级为写事务是死锁的经典来源）。
	db, err := sql.Open("sqlite", dsn+"?_pragma=busy_timeout(5000)&_txlock=immediate")
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

	return &Store{db: db, cipher: c}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB 暴露底层连接，供尚未封装的查询使用（样本浏览器等）。
func (s *Store) DB() *sql.DB { return s.db }

func nowMS() int64 { return time.Now().UnixMilli() }
