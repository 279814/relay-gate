package api

import "net/http"

func (s *Server) getSecurityEvidenceMetadata(w http.ResponseWriter, r *http.Request) {
	evidence, err := s.st.SecurityFindingEvidence(r.Context(), r.PathValue("id"), false)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, evidence)
}
func (s *Server) viewSecurityEvidence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.sessionOK(r) {
		writeJSON(w, http.StatusForbidden, errBody{"查看未脱敏证据须使用有效 Cookie 会话并再次认证"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if !s.passwordOK(body.Password) {
		writeSampleReauthFailure(w, http.StatusForbidden)
		return
	}
	evidence, err := s.st.SecurityFindingEvidence(r.Context(), r.PathValue("id"), true)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evidence)
}
