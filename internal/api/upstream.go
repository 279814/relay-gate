package api

import (
	"net/http"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// upstreamOut 是 Upstream 的出站表示。
//
// 单独定义而不是直接序列化 model.Upstream，为的是**结构性地**保证 key 不会回显：
// 出站类型里根本没有明文 key 字段，就不存在「某个分支忘了脱敏」的可能。
type upstreamOut struct {
	*model.Upstream
	APIKey      string `json:"api_key"`        // 覆盖父结构，始终是脱敏值
	APIKeyIsSet bool   `json:"api_key_is_set"` // 让前端知道「留空=不改」而非「没有 key」
}

func maskUpstream(u *model.Upstream) upstreamOut {
	masked := store.MaskKey(u.APIKey)
	isSet := u.APIKey != ""
	cp := *u
	cp.APIKey = ""
	return upstreamOut{Upstream: &cp, APIKey: masked, APIKeyIsSet: isSet}
}

func (s *Server) listUpstreams(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListUpstreams()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]upstreamOut, 0, len(list))
	for _, u := range list {
		out = append(out, maskUpstream(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	u, err := s.st.GetUpstream(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, maskUpstream(u))
}

func (s *Server) createUpstream(w http.ResponseWriter, r *http.Request) {
	var u model.Upstream
	u.Enabled = true // 新建默认启用；显式传 false 可覆盖
	if err := decodeJSON(r, &u); err != nil {
		s.writeErr(w, err)
		return
	}
	u.ID = 0
	if err := s.st.CreateUpstream(&u); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("新增 upstream", "id", u.ID, "name", u.Name)
	// 新建的站还没有 Route，没什么可探的。等 Route 建好时由那边触发。
	writeJSON(w, http.StatusCreated, maskUpstream(&u))
}

func (s *Server) updateUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// 以库中现值为基底：PUT 未提供的字段保持原样，
	// 尤其 api_key 留空表示「不改 key」（前端拿到的是脱敏值，不能当真 key 回写）。
	cur, err := s.st.GetUpstream(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// 留一份改动前的副本用于比对。必须在置空 APIKey **之前**拷贝：
	// 置空后再比就会把「没改 key」误判成「key 从有变没」，于是每次
	// 保存都触发一轮全站重探。
	before := *cur

	cur.APIKey = "" // 置空 = 不改；若请求体带了新 key 会覆盖它
	if err := decodeJSON(r, cur); err != nil {
		s.writeErr(w, err)
		return
	}
	cur.ID = id
	if err := s.st.UpdateUpstream(cur); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("更新 upstream", "id", id, "name", cur.Name)

	fresh, err := s.st.GetUpstream(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// §4.5：改了 key / 地址 / 探活头就立刻重探整站，不等下一个周期。
	// 用 fresh 而不是 cur 比对：cur 的 APIKey 可能是「留空表示不改」的空串，
	// 而 fresh 是库里的真实现值。
	if probeAffectingUpstream(&before, fresh) || (!before.Enabled && fresh.Enabled) {
		s.invalidateUpstream(id)
	}
	writeJSON(w, http.StatusOK, maskUpstream(fresh))
}

func (s *Server) deleteUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.DeleteUpstream(id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("删除 upstream", "id", id)
	w.WriteHeader(http.StatusNoContent)
}
