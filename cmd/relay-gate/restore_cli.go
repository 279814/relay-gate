// restore_cli.go — P0-17 offline db check-backup / restore.
//
// Dispatched from main before Store.Open / listeners / workers.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/279814/relay-gate/internal/config"
	"github.com/279814/relay-gate/internal/store"
)

type dbFlags struct {
	cmd                   string
	database              string
	manifest              string
	execute               bool
	acceptDataReplacement bool
	acceptReaderContract  string
}

func parseDBFlags(args []string) (dbFlags, error) {
	if len(args) == 0 {
		return dbFlags{}, fmt.Errorf("用法: relay-gate db <check-backup|restore> ...")
	}
	f := dbFlags{cmd: args[0]}
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--database" && i+1 < len(args):
			i++
			f.database = args[i]
		case strings.HasPrefix(a, "--database="):
			f.database = strings.TrimPrefix(a, "--database=")
		case a == "--manifest" && i+1 < len(args):
			i++
			f.manifest = args[i]
		case strings.HasPrefix(a, "--manifest="):
			f.manifest = strings.TrimPrefix(a, "--manifest=")
		case a == "--execute":
			f.execute = true
		case a == "--accept-data-replacement":
			f.acceptDataReplacement = true
		case a == "--accept-reader-contract" && i+1 < len(args):
			i++
			f.acceptReaderContract = args[i]
		case strings.HasPrefix(a, "--accept-reader-contract="):
			f.acceptReaderContract = strings.TrimPrefix(a, "--accept-reader-contract=")
		default:
			return dbFlags{}, fmt.Errorf("未知参数: %s", a)
		}
	}
	if f.database == "" || f.manifest == "" {
		return dbFlags{}, fmt.Errorf("需要 --database 与 --manifest")
	}
	return f, nil
}

func runDBCLI(args []string, stdout, stderr io.Writer) int {
	f, err := parseDBFlags(args)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	if f.cmd == "restore" && (!f.execute || !f.acceptDataReplacement || f.acceptReaderContract == "") {
		fmt.Fprintf(stderr, "restore 需要 --execute --accept-data-replacement --accept-reader-contract <exact>\n")
		return exitUsage
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "加载配置: %v\n", err)
		return exitFail
	}
	cipher, err := store.NewCipher(cfg.EncKey)
	if err != nil {
		fmt.Fprintf(stderr, "打开加密: %v\n", err)
		return exitFail
	}

	switch f.cmd {
	case "check-backup":
		manifest, err := store.CheckBackup(context.Background(), f.database, f.manifest, cipher)
		if err != nil {
			fmt.Fprintf(stderr, "check-backup 失败: %v\n", err)
			return exitFail
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(manifest); err != nil {
			fmt.Fprintf(stderr, "输出 manifest: %v\n", err)
			return exitFail
		}
		fmt.Fprintf(stdout, "ReaderContract=%s\nPairedBuildID=%s\nSourceSchema=%d\n",
			manifest.ReaderContract, manifest.PairedBuildID, manifest.SourceSchema)
		return exitOK
	case "restore":
		result, err := store.RestoreDatabase(context.Background(), f.database, f.manifest, cipher,
			f.acceptDataReplacement, f.acceptReaderContract)
		if err != nil {
			if errors.Is(err, store.ErrRestoreRejected) || errors.Is(err, store.ErrRestorePending) {
				fmt.Fprintf(stderr, "restore 拒绝: %v\n", err)
			} else {
				fmt.Fprintf(stderr, "restore 失败: %v\n", err)
			}
			return exitFail
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(stderr, "输出结果: %v\n", err)
			return exitFail
		}
		return exitOK
	default:
		fmt.Fprintf(stderr, "未知 db 子命令: %s\n", f.cmd)
		return exitUsage
	}
}
