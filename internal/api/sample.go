package api

import (
	"net/http"
	"strconv"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// listSamples 返回样本列表（不含 body，见 store.ListSamples 的说明）。
func (s *Server) listSamples(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.SampleFilter{
		RouteID:    queryInt64(q.Get("route_id")),
		UpstreamID: queryInt64(q.Get("upstream_id")),
		Outcome:    model.Outcome(q.Get("outcome")),
		Limit:      int(queryInt64(q.Get("limit"))),
		BeforeID:   queryInt64(q.Get("before_id")),
	}
	list, err := s.st.ListSamples(f)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	total, err := s.st.CountSamples()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"samples": list, "total": total})
}

// getSample 返回单条样本的全部内容，含三份 body。
//
// body 是 []byte，encoding/json 会编成 base64 —— 这是刻意的：
// 样本 body 可能含非法 UTF-8（对话里的二进制片段、被截断的多字节字符），
// 直接当字符串编码会被替换成 U+FFFD，而「到底是哪些字节」正是这个功能的全部意义。
func (s *Server) getSample(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	smp, err := s.st.GetSample(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, smp)
}

func (s *Server) pinSample(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var body struct {
		Pinned bool `json:"pinned"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.SetSamplePinned(id, body.Pinned); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "pinned": body.Pinned})
}

// clearSamples 是 UI 的「一键清空」（§3.6.3d）。
// 默认保留置顶的 —— 置顶正是「这条我要留着」的意思，一键清空不该无视它。
func (s *Server) clearSamples(w http.ResponseWriter, r *http.Request) {
	keepPinned := r.URL.Query().Get("keep_pinned") != "false"
	n, err := s.st.ClearSamples(keepPinned)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("清空样本", "deleted", n, "keep_pinned", keepPinned)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

func queryInt64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
