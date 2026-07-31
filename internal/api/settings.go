package api

import (
	"net/http"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.st.GetSettings()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// 把硬下限一并告知前端，让输入框能自己限制，而不是等提交后才报错。
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": st,
		"limits": map[string]int{
			"min_real_first_token_sec": model.MinRealFirstTokenSec,
		},
	})
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	cur, err := s.st.GetSettings()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// 以现值为基底做部分更新：只想改一个超时不必提交整份配置。
	if err := decodeJSON(r, &cur); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.SaveSettings(cur); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("更新全局设置", "real_first_token_sec", cur.RealFirstTokenSec,
		"sample_enabled", cur.SampleEnabled)
	writeJSON(w, http.StatusOK, cur)
}

// getState / setState 是服务总闸（§4.8）。
// 管理端点在 paused 下仍必须可用，否则暂停后无法通过 UI 恢复。
func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	st, err := s.st.GetRunState()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": string(st)})
}

func (s *Server) setState(w http.ResponseWriter, r *http.Request) {
	var body struct {
		State string `json:"state"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.SetRunState(store.RunState(body.State)); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("切换服务状态", "state", body.State)
	writeJSON(w, http.StatusOK, map[string]string{"state": body.State})
}
