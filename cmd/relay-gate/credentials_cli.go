package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/279814/relay-gate/internal/credential"
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
	b := &credential.Bootstrap{DataDir: dataDir, Out: stdout}
	_, err := b.Run()
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
	err := m.Run()
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
	_, err := credential.ResetAdmin(dataDir, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "credentials reset-admin 失败: %v\n", err)
		return exitFail
	}
	fmt.Fprintf(stderr, "credentials reset-admin 完成（新密码仅上方显示一次）。\n")
	return exitOK
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
