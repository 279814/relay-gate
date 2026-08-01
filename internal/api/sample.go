package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// listSamples 返回样本列表（不含 body，见 store.ListSamples 的说明）。
func (s *Server) listSamples(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var qerr error
	num := func(name string) int64 {
		n, err := queryInt64(q.Get(name))
		if err != nil && qerr == nil {
			qerr = fmt.Errorf("%w: 参数 %s 不是合法整数：%q", model.ErrValidation, name, q.Get(name))
		}
		return n
	}
	f := store.SampleFilter{
		RouteID:    num("route_id"),
		UpstreamID: num("upstream_id"),
		Outcome:    model.Outcome(q.Get("outcome")),
		// req_id 让「从日志跳到样本」成为一次精确查询（M6，§3.7.3）。
		//
		// 少了它，前端只能拉一页回来自己找 —— 而那对「比最近一页更早的
		// 请求」会**静默找不到**，正是排查历史故障时要点的那些。
		ReqID:    q.Get("req_id"),
		Limit:    int(num("limit")),
		BeforeID: num("before_id"),
	}
	// 参数写错了要说出来。静默当成 0 的话，?before_id=abc 会从头开始返回，
	// 看着像「翻页转了一圈」，而真正的原因是那个 typo。
	if qerr != nil {
		s.writeErr(w, qerr)
		return
	}
	if f.Outcome != "" && !f.Outcome.Valid() {
		s.writeErr(w, fmt.Errorf("%w: 未知的 outcome：%q", model.ErrValidation, f.Outcome))
		return
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

// queryInt64 解析查询参数。空串是「没传」，返回 0 且不算错。
func queryInt64(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.ParseInt(s, 10, 64)
}
