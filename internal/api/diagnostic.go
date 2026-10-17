package api

import (
	"context"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/sample"
)

func (s *Server) diagnosticKeys(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	if s.st == nil {
		return nil, true
	}
	keys, err := s.st.DiagnosticRedactionKeys(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"诊断脱敏凭据暂不可读，请修复后重试"})
		return nil, false
	}
	return keys, true
}

// Error text may contain the newly committed key even when publishing the new
// routing snapshot failed. Read current DB credentials, never stale routing.
// A key-read failure logs only fixed text, without recursively logging errors.
func (s *Server) diagnosticError(err error) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if s.st == nil {
		return "诊断脱敏凭据不可用，已省略错误详情"
	}
	keys, readErr := s.st.DiagnosticRedactionKeys(ctx)
	if readErr != nil {
		return "诊断脱敏凭据不可用，已省略错误详情"
	}
	return sample.RedactDiagnosticText(err.Error(), keys)
}

func (s *Server) writeExecutionDetail(w http.ResponseWriter, r *http.Request, execution model.ProbeExecution) {
	keys, ok := s.diagnosticKeys(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, redactExecutionDetail(execution, keys))
}
