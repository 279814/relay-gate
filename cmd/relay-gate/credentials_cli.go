package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/store"
)

func runCredentialsCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "用法: relay-gate credentials <bootstrap|migrate|reset-admin>\n")
		return exitUsage
	}
	switch args[0] {
	case "bootstrap":
		return runCredentialsBootstrap(args[1:], stdout, stderr)
	case "migrate":
		return runCredentialsMigrate(args[1:], stdout, stderr)
	case "reset-admin":
		return runCredentialsResetAdmin(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知 credentials 子命令: %s\n", args[0])
		return exitUsage
	}
}

func runCredentialsBootstrap(args []string, stdout, stderr io.Writer) int {
	dataDir := "data"
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--data-dir" && i+1 < len(args):
			i++
			dataDir = args[i]
		case strings.HasPrefix(a, "--data-dir="):
			dataDir = strings.TrimPrefix(a, "--data-dir=")
		default:
			fmt.Fprintf(stderr, "未知参数: %s\n", a)
			return exitUsage
		}
	}
	if strings.TrimSpace(dataDir) == "" {
		fmt.Fprintf(stderr, "需要 --data-dir\n")
		return exitUsage
	}
	lock, err := acquireDataDirLock(dataDir, os.Getenv("RELAY_DB"))
	if err != nil {
		fmt.Fprintf(stderr, "credentials bootstrap 失败: %v\n", err)
		return exitFail
	}
	defer lock.Close()
	b := &credential.Bootstrap{DataDir: dataDir, Out: stdout}
	_, err = b.Run()
	if err != nil {
		fmt.Fprintf(stderr, "credentials bootstrap 失败: %v\n", err)
		return exitFail
	}
	fmt.Fprintf(stderr, "credentials bootstrap 完成（三项明文仅上方显示一次）。\n")
	return exitOK
}

func runCredentialsMigrate(args []string, stdout, stderr io.Writer) int {
	dataDir := "data"
	dbPath := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--data-dir" && i+1 < len(args):
			i++
			dataDir = args[i]
		case strings.HasPrefix(a, "--data-dir="):
			dataDir = strings.TrimPrefix(a, "--data-dir=")
		case a == "--db" && i+1 < len(args):
			i++
			dbPath = args[i]
		case strings.HasPrefix(a, "--db="):
			dbPath = strings.TrimPrefix(a, "--db=")
		default:
			fmt.Fprintf(stderr, "未知参数: %s\n", a)
			return exitUsage
		}
	}
	if strings.TrimSpace(dataDir) == "" {
		fmt.Fprintf(stderr, "需要 --data-dir\n")
		return exitUsage
	}
	if dbPath == "" {
		dbPath = envOr("RELAY_DB", "data/relay-gate.db")
	}
	lock, err := acquireDataDirLock(dataDir, dbPath, os.Getenv("RELAY_DB"))
	if err != nil {
		fmt.Fprintf(stderr, "credentials migrate 失败: %v\n", err)
		return exitFail
	}
	defer lock.Close()
	var relays []string
	for _, k := range strings.Split(os.Getenv("RELAY_KEYS"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			relays = append(relays, k)
		}
	}
	m := &credential.Migration{
		DataDir:   dataDir,
		DBPath:    dbPath,
		EncKey:    os.Getenv("ENCRYPTION_KEY"),
		AdminPW:   os.Getenv("ADMIN_PASSWORD"),
		RelayKeys: relays,
		Out:       stdout,
	}
	err = m.Run()
	if err != nil {
		fmt.Fprintf(stderr, "credentials migrate 失败: %v\n", err)
		if errors.Is(err, credential.ErrMigrationComplete) {
			return exitFail
		}
		return exitFail
	}
	fmt.Fprintf(stderr, "credentials migrate 完成（未打印旧 Secret）。\n")
	return exitOK
}

func runCredentialsResetAdmin(args []string, stdout, stderr io.Writer) int {
	dataDir := "data"
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--data-dir" && i+1 < len(args):
			i++
			dataDir = args[i]
		case strings.HasPrefix(a, "--data-dir="):
			dataDir = strings.TrimPrefix(a, "--data-dir=")
		default:
			fmt.Fprintf(stderr, "未知参数: %s\n", a)
			return exitUsage
		}
	}
	if strings.TrimSpace(dataDir) == "" {
		fmt.Fprintf(stderr, "需要 --data-dir\n")
		return exitUsage
	}
	lock, err := acquireDataDirLock(dataDir, os.Getenv("RELAY_DB"))
	if err != nil {
		fmt.Fprintf(stderr, "credentials reset-admin 失败: %v\n", err)
		return exitFail
	}
	defer lock.Close()
	_, err = credential.ResetAdmin(dataDir, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "credentials reset-admin 失败: %v\n", err)
		return exitFail
	}
	fmt.Fprintf(stderr, "credentials reset-admin 完成（新密码仅上方显示一次）。\n")
	return exitOK
}

// acquireDataDirLock 取得服务端持有的同一把数据目录锁（见 lockDataDir）。
// 服务端在跑时这里以 ErrInstanceLocked 失败，不碰 secrets。
func acquireDataDirLock(dataDir string, dbCandidates ...string) (*dataDirLock, error) {
	return lockDataDir(dataDir, instanceDBPath(dataDir, dbCandidates...))
}

// dataDirLock 是 §12.3 的数据目录独占锁加上数据库自身的实例锁。
// db 与数据目录锁是同一文件时 db == dir。
type dataDirLock struct {
	dir *store.InstanceLock
	db  *store.InstanceLock
}

// lockDataDir 先取 <dataDir>/relay-gate.db 的实例锁作为数据目录锁 —— 不论 RELAY_DB
// 用什么文件名，写同一 dataDir/secrets 的进程都争这一把；dbPath 是另一个文件时再取它的
// 实例锁（OpenLocked 要求与数据库路径一致）。
func lockDataDir(dataDir, dbPath string) (*dataDirLock, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录 %s: %w", dataDir, err)
	}
	dirDB := filepath.Join(dataDir, "relay-gate.db")
	dir, err := store.AcquireInstanceLock(dirDB)
	if err != nil {
		return nil, err
	}
	l := &dataDirLock{dir: dir, db: dir}
	if strings.TrimSpace(dbPath) != "" && !samePath(dbPath, dirDB) {
		db, err := store.AcquireInstanceLock(dbPath)
		if err != nil {
			_ = dir.Close()
			return nil, err
		}
		l.db = db
	}
	return l, nil
}

// Close 释放两把锁中尚未移交给 Store 的部分。
func (l *dataDirLock) Close() error {
	if l == nil {
		return nil
	}
	return errors.Join(l.db.Close(), l.dir.Close())
}

// instanceDBPath 选出落在 dataDir 下的数据库路径；都不在时用服务端默认文件名。
func instanceDBPath(dataDir string, candidates ...string) string {
	want, err := filepath.Abs(dataDir)
	if err == nil {
		for _, c := range candidates {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if samePath(filepath.Dir(c), want) {
				return c
			}
		}
	}
	return filepath.Join(dataDir, "relay-gate.db")
}

func samePath(a, b string) bool {
	a, errA := filepath.Abs(a)
	b, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	return a == b || (runtime.GOOS == "windows" && strings.EqualFold(a, b))
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
