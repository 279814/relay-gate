package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/279814/relay-gate/internal/credential"
)

func runCredentialsCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "用法: relay-gate credentials <bootstrap>\n")
		return exitUsage
	}
	switch args[0] {
	case "bootstrap":
		return runCredentialsBootstrap(args[1:], stdout, stderr)
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
		if errors.Is(err, credential.ErrBootstrapComplete) {
			return exitFail
		}
		return exitFail
	}
	fmt.Fprintf(stderr, "credentials bootstrap 完成（三项明文仅上方显示一次）。\n")
	return exitOK
}
