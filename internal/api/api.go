// Package api 提供管理端 REST 接口。
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// InFlightView 暴露每个 Route 的在途请求数。由 health.Tracker 实现。
type InFlightView interface {
	Snapshot() map[int64]int
}

// SampleStats 暴露样本记录器的落库/丢弃计数。由 sample.Recorder 实现。
//
// 请求日志记录器（sample.LogRecorder）满足同一个签名，所以两者共用这个
// 接口。不为它单开一个同形状的类型 —— 那只会让「这两个计数是一回事」
// 这个事实变得不明显。
type SampleStats interface {
	Stats() (written, dropped int64)
}

type Server struct {
	st  *store.Store
	log *slog.Logger
	// inFlight、samples 与 reqLogs 可以为 nil（测试里常只关心 CRUD），
	// runtime 端点会据此把对应字段留空而不是崩。
	inFlight InFlightView
	samples  SampleStats
	reqLogs  SampleStats

	// 探活链路。同样可以为 nil —— 探活未启用时相关端点回 503，
	// 而不是让整个管理接口不可用（管理端点必须始终可用，§4.8）。
	healthView HealthView
	gate       GateView
	prober     Prober

	// cost 是探活成本计数器（§5.2d）。为 nil 时对应端点回 503。
	cost CostView

	// invalidator 让配置写入立刻触发探活（§4.5）。为 nil 时静默跳过 ——
	// 那只意味着回到「等下一个探活周期」，不是错误。
	invalidator ConfigInvalidator

	// adminPW 由 Routes 装配时写入，会话与 Bearer 两条路径共用。
	adminPW  string
	sessions *sessionStore
}

func New(st *store.Store, log *slog.Logger) *Server {
	return &Server{st: st, log: log, sessions: newSessionStore()}
}

// WithRuntime 接上运行时观测源。分成单独的 setter 而不是加构造参数，
// 是因为这几者属于转发链路，而 api.Server 的主职责是配置 CRUD。
//
// 三个参数都可以为 nil。日志记录器（M6）作为第三个参数追加在末尾，
// 而不是另开一个 WithRequestLogs —— 它与前两个是同一类东西
// （「此刻转发链路上正在发生什么」），拆开只会让装配代码多一行。
func (s *Server) WithRuntime(inFlight InFlightView, samples, reqLogs SampleStats) *Server {
	s.inFlight, s.samples, s.reqLogs = inFlight, samples, reqLogs
	return s
}

// ── 响应helper ────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

type errBody struct {
	Error string `json:"error"`
}

// writeErr 把领域错误映射到 HTTP 状态码。
// 校验类错误一律 400 并把原文回给调用方——这些错误信息是刻意写给人看的，
// 吞掉它们会让配置出错时只剩一个无信息的 400。
func (s *Server) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody{"not found"})
	case errors.Is(err, model.ErrValidation):
		msg := strings.TrimPrefix(err.Error(), "validation: ")
		writeJSON(w, http.StatusBadRequest, errBody{msg})
	default:
		s.log.Error("内部错误", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody{"internal error"})
	}
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	// 拒绝未知字段：配置接口写错字段名（如 baseurl 而非 base_url）时，
	// 静默忽略会让人以为设置生效了，实际是默认值在跑。
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return model.WrapValidation("请求体不是合法 JSON: %v", err)
	}
	return nil
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, model.WrapValidation("路径中的 id 不合法")
	}
	return id, nil
}
