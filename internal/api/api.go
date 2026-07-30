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

type Server struct {
	st  *store.Store
	log *slog.Logger
}

func New(st *store.Store, log *slog.Logger) *Server {
	return &Server{st: st, log: log}
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
