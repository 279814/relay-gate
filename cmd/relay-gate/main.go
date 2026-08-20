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
	"sync"
	"syscall"
	"time"

	"github.com/279814/relay-gate/internal/api"
	"github.com/279814/relay-gate/internal/config"
	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/proxy"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/web"
)

// version 由构建时注入（Dockerfile 的 -ldflags "-X main.version=..."）。
//
// 存在的理由很实际：出问题时第一个要回答的是「线上跑的到底是哪个版本」。
// 没有它就只能比对二进制的 mtime，而容器里那个时间是镜像构建时间，
// 与代码版本没有可靠对应。
//
// 默认 dev 而不是空串：空串在日志里看起来像「字段丢了」，
// 而 dev 明确表示「这是本地构建的，不是发布产物」。
var version = "dev"

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
	// 转发路径读的是 livecfg 的缓存视图，这里只为启动日志与首个 /healthz。
	runState, err := st.GetRunState()
	if err != nil {
		return fmt.Errorf("读取运行状态: %w", err)
	}

	cfgSrc := livecfg.New(st, log)
	tracker := health.NewTracker(cfgSrc)
	gate := health.NewUpstreamGate()

	// 样本记录（§3.6）。开关与保留策略都在 Settings 里、都可热改
	// （前者每请求现读，后者每次清理现读）。只有队列大小是启动时定格的 ——
	// 它是 channel 的容量，改它必须重启。
	settings, err := cfgSrc.Settings()
	if err != nil {
		return fmt.Errorf("读取设置: %w", err)
	}
	recorder := sample.NewRecorder(st, settings, cfgSrc, log)
	// 放在 Shutdown 之后收尾：关闭前那几条样本往往正是故障现场。
	defer recorder.Close()

	// 请求日志（M6）：每次尝试一行，含被重试丢弃的那些。
	//
	// 与样本各是一套独立的旋钮（开关、保留策略、队列都分开）。样本可以关，
	// 日志不该跟着关 —— 日志是判断「重试策略有没有用」的唯一依据，而那个
	// 判断恰恰在「样本太占地方所以关掉、只留统计」的场景下最需要。
	logRecorder := sample.NewLogRecorder(st, settings, cfgSrc, log)
	defer logRecorder.Close()

	// 出站目标解析（§7.1）。真实转发、探活与 count_tokens 共用这一个
	// Resolver —— 各拼一套 URL 的话，探活通过不代表真实请求能通，
	// 而那个差异只在生产流量上显形。
	//
	// 在 main 里显式装配三样东西：Cipher 提供 keyed digest（URL 证据不能用
	// 裸 SHA，见 §4.3），Store 提供 Endpoint 配置与 legacy URL 解密。
	// P0-10 的原子 ConfigBundle 上线后只换 EndpointConfigSource，规则不动。
	targets := outbound.NewProvider(st, st, outbound.NewResolver(cipher))

	// 真实请求的结果回写健康状态（§3.5）。这是**最快**的故障发现路径 ——
	// 探活有周期，真实请求没有延迟，站挂掉那一刻就有请求撞上去。
	fwd := proxy.NewHandler(cfgSrc, tracker, recorder, cfg.RelayKeys, log).
		WithTargets(targets, st).
		WithHealthReporter(probe.NewReporter(tracker)).
		WithLogSink(logRecorder)
	// 关掉缓存的出站连接。放在 Shutdown 之后：在途的流式请求还要用它们。
	defer fwd.CloseIdleConnections()

	// 探活（§4）。Transport 由 fwd 提供，与转发共用连接池 ——
	// 探活顺带把连接热着，真实请求就省掉一次 TLS 握手。
	//
	// 探活成本计数（§5.2d）落库跨重启：纯内存计数在重启后归零，
	// 「今日 L1 次数」会一天里越报越少 —— 会骗人的计数器比没有更糟。
	cost := probe.NewCost()
	costPersister := probe.NewCostPersister(cost, st, log)
	costPersister.Restore()

	sched := probe.NewScheduler(cfgSrc, fwd, tracker, gate, log).
		WithCost(cost).
		WithTargets(targets, st)
	persister := health.NewPersister(tracker, st, log)

	// 探活与落库跟着这个 ctx 收尾。放在 srv.Shutdown 之后取消：
	// 关闭期间在途的真实请求仍会回写健康状态，Persister 还要把它刷进库。
	bgCtx, stopBG := context.WithCancel(context.Background())
	var bg sync.WaitGroup
	bg.Add(3)
	go func() { defer bg.Done(); sched.Run(bgCtx) }()
	go func() { defer bg.Done(); persister.Run(bgCtx) }()
	go func() { defer bg.Done(); costPersister.Run(bgCtx) }()
	defer func() {
		stopBG()
		bg.Wait()
	}()

	mux := http.NewServeMux()
	// WithRuntime 把在途计数、样本与日志的丢弃数接到 /admin/api/runtime ——
	// 丢弃是静默的，没有出口的话「样本怎么少了几条」就无从查起。
	// 日志的丢弃更要紧：它会让重试统计偏低，而那个统计正是用来决定
	// 「要不要保留重试」的。
	//
	// WithInvalidator 让配置写入立刻触发探活（§4.5）。它**只**触发探活，
	// 不负责配置生效 —— 那仍由 livecfg 的 2s TTL 保证，所以漏调一处
	// 只是慢一点，不会变成「改了不生效」。
	mux.Handle("/admin/api/", api.New(st, log).
		WithRuntime(tracker, recorder, logRecorder).
		WithHealth(tracker, gate, sched).
		WithCost(cost).
		WithInvalidator(sched).
		Routes(cfg.AdminPW))
	fwd.Routes(mux)

	// 管理界面（§6）。挂在 /admin/ 下，与 /admin/api/ 并存 ——
	// ServeMux 的最长前缀匹配保证 API 请求不会掉进这里。
	//
	// 静态资源刻意不鉴权：它们只有 HTML/CSS/JS，数据全在 /admin/api/ 后面。
	// 反过来说也**不能**鉴权 —— 登录页自己就是静态资源。
	mux.Handle("/admin/", web.Handler())
	// /healthz 报的是**进程活着**，不代表有可用上游 —— 那要看 /admin/api/state。
	// 混在一起会让容器编排在所有上游都挂时重启进程，而重启治不了上游。
	//
	// 带上 version：这是唯一不需要凭据就能问出「线上跑的是哪个版本」的地方，
	// 而部署之后第一个要回答的往往就是它（尤其「我到底推上去了没有」）。
	// 版本号不是秘密 —— 仓库是自己的，且它换不来任何攻击面。
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		state, err := cfgSrc.RunState()
		if err != nil {
			state = runState // 库暂时读不出来时报启动时的状态，别让健康检查失败
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","state":%q,"version":%q}`, state, version)
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
		log.Info("relay-gate 已启动", "version", version, "addr", cfg.Addr, "db", cfg.DBPath,
			"state", runState, "relay_keys", len(cfg.RelayKeys),
			"endpoints", "/v1/messages /v1/responses /v1/chat/completions "+
				"/v1/messages/count_tokens /v1/models")
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
