// Command relay-gate 是主动探活 + 优先级路由的 LLM 中转网关。
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/279814/relay-gate/internal/api"
	"github.com/279814/relay-gate/internal/config"
	"github.com/279814/relay-gate/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "启动失败：%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if dir := filepath.Dir(cfg.DBPath); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("创建数据目录 %s: %w", dir, err)
		}
	}

	cipher, err := store.NewCipher(cfg.EncKey)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath, cipher)
	if err != nil {
		return err
	}
	defer st.Close()

	// 启动时读一次运行状态：暂停时重启不应自动跑起来（§4.8）。
	runState, err := st.GetRunState()
	if err != nil {
		return fmt.Errorf("读取运行状态: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/admin/api/", api.New(st, log).Routes(cfg.AdminPW))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","state":%q}`, runState)
	})

	srv := &http.Server{
		Addr:    cfg.Addr,
		Handler: mux,
		// 不设 WriteTimeout：真实请求的首 Token 可达 20 分钟（§4.2），
		// 一个粗粒度的写超时会把正常的长思考直接掐断。
		// 超时控制在转发层按三段独立实现，不靠 Server 级的钝刀。
		ReadHeaderTimeout: 30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("relay-gate 已启动", "addr", cfg.Addr, "db", cfg.DBPath,
			"state", runState, "relay_keys", len(cfg.RelayKeys))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// 等信号或启动错误
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return fmt.Errorf("监听 %s: %w", cfg.Addr, err)
	case sig := <-sigCh:
		log.Info("收到信号，开始优雅关闭", "signal", sig.String())
	}

	// 给进行中的流式请求留出收尾时间。真实对话可能正在传输，
	// 硬关会让客户端丢掉一次完整回复。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("关闭超时，仍有请求未结束: %w", err)
	}
	log.Info("已停止")
	return nil
}
