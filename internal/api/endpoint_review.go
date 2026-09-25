package api

import (
	"net/http"

	"github.com/279814/relay-gate/internal/model"
)

// postConfirmEndpointReview clears NeedsReview after converting legacy_exact
// to canonical with an explicit url_override (§19.2).
//
// Body: { "url_override": "...", "expected_revision": N }
// url_override is required so we never silently guess a multi-endpoint mapping.
func (s *Server) postConfirmEndpointReview(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if s.probeAdmin == nil {
		s.writeErr(w, model.WrapValidation("probe admin 未装配"))
		return
	}
	var body struct {
		URLOverride      string `json:"url_override"`
		ExpectedRevision int64  `json:"expected_revision"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.URLOverride == "" {
		s.writeErr(w, model.WrapValidation("url_override 必填：审核转换不得静默猜测完整 URL"))
		return
	}
	if body.ExpectedRevision < 1 {
		s.writeErr(w, model.WrapValidation("expected_revision 必须为正数"))
		return
	}
	cur, err := s.st.GetEndpoint(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	in := *cur
	in.URLMode = model.EndpointURLCanonical
	in.URLOverride = body.URLOverride
	in.LegacyFullURLID = 0
	in.LegacyFullURLRevision = 0
	in.LegacyCompatRealOnly = false
	in.NeedsReview = false
	ep, err := s.probeAdmin.UpdateEndpoint(r.Context(), id, body.ExpectedRevision, in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.invalidateUpstream(ep.UpstreamID)
	// confirm-review 写入 url_override，须立刻发布 livecfg Probe 快照。
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ep)
}
