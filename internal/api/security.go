package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
	"github.com/279814/relay-gate/internal/store"
)

// SecurityCenter is the narrow P3 finding store used by admin API.
type SecurityCenter interface {
	List(severity security.Severity, limit int) []security.Finding
	Count() int
	Record(f security.Finding) security.Finding
}

// WithSecurityCenter injects the P3 Security Center.
func (s *Server) WithSecurityCenter(c SecurityCenter) *Server {
	s.security = c
	return s
}

// WithAlertMailer injects SMTP alert sender.
func (s *Server) WithAlertMailer(m *security.AlertMailer) *Server {
	s.mailer = m
	return s
}

func (s *Server) listSecurityFindings(w http.ResponseWriter, r *http.Request) {
	sev := security.Severity(r.URL.Query().Get("severity"))
	limit, err := queryInt64(r.URL.Query().Get("limit"))
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: limit", model.ErrValidation))
		return
	}
	if r.URL.Query().Get("limit") == "" {
		limit = 50
	}
	// Prefer durable store when available; fall back to in-memory center.
	if s.st != nil {
		list, err := s.st.ListSecurityFindings(string(sev), int(limit))
		if err == nil {
			total, _ := s.st.CountSecurityFindings()
			writeJSON(w, http.StatusOK, map[string]any{"findings": list, "total": total})
			return
		}
	}
	if s.security == nil {
		writeJSON(w, http.StatusOK, map[string]any{"findings": []any{}, "total": 0})
		return
	}
	list := s.security.List(sev, int(limit))
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": list,
		"total":    s.security.Count(),
	})
}

// postSecurityScan runs a passive scan on caller-provided plain text (admin diagnostic).
func (s *Server) postSecurityScan(w http.ResponseWriter, r *http.Request) {
	if s.security == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"security center unavailable"})
		return
	}
	var body struct {
		Text     string `json:"text"`
		Upstream string `json:"upstream"`
		ReqID    string `json:"req_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	found := security.ScanText(body.Text, "admin_scan")
	out := make([]security.Finding, 0, len(found))
	for _, f := range found {
		f.Upstream = body.Upstream
		f.ReqID = body.ReqID
		f.ScannerVersion = security.ScannerVersion
		f.RuleVersion = security.RuleVersion
		f.BytesScanned = int64(len(body.Text))
		out = append(out, s.security.Record(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out, "count": len(out)})
}

// postSecurityCanary runs a one-shot Active Upstream canary via manual probe (§14.4).
func (s *Server) postSecurityCanary(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UpstreamID int64  `json:"upstream_id"`
		RouteID    int64  `json:"route_id"`
		ProbeMode  string `json:"probe_mode"`
		Note       string `json:"note"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	routeID := body.RouteID
	if routeID == 0 && body.UpstreamID != 0 && s.st != nil {
		page, err := s.st.ListRoutesPage(r.Context(), model.RouteFilter{})
		if err == nil {
			for _, rt := range page.Items {
				if rt.UpstreamID == body.UpstreamID {
					routeID = rt.ID
					break
				}
			}
		}
	}
	if routeID == 0 {
		s.writeErr(w, fmt.Errorf("%w: route_id required", model.ErrValidation))
		return
	}
	if s.st != nil {
		rt, err := s.st.GetRoute(routeID)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		up, err := s.st.GetUpstream(rt.UpstreamID)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		if up.ProbeMode == model.ProbeModeLazy {
			writeJSON(w, http.StatusBadRequest, errBody{"Lazy Upstream 禁止主动 canary；请先切 Active"})
			return
		}
	} else if model.ProbeMode(strings.ToLower(body.ProbeMode)) == model.ProbeModeLazy {
		writeJSON(w, http.StatusBadRequest, errBody{"Lazy Upstream 禁止主动 canary；请先切 Active"})
		return
	}

	result := map[string]any{
		"accepted": true,
		"route_id": routeID,
		"mode":     "manual",
	}
	if s.probeAdmin != nil {
		exec, err := s.probeAdmin.RunManual(r.Context(), routeID)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		result["execution_id"] = exec.ID
		result["success"] = exec.Success
		result["status_code"] = exec.StatusCode
		result["error_class"] = exec.ErrorClass
		if s.security != nil {
			detail := strings.TrimSpace(body.Note)
			if exec.RedactedDetail != "" {
				if detail != "" {
					detail += "; "
				}
				detail += exec.RedactedDetail
			}
			sev := security.SeverityInfo
			if !exec.Success {
				sev = security.SeverityMedium
			}
			s.security.Record(security.Finding{
				Severity: sev,
				Category: "canary_manual",
				Summary:  "手动 canary 已执行",
				Detail:   detail,
				Source:   "canary",
				RouteID:  routeID,
			})
		}
	} else if s.security != nil {
		s.security.Record(security.Finding{
			Severity: security.SeverityInfo,
			Category: "canary_manual",
			Summary:  "手动 canary 已记录（探活未装配）",
			Detail:   strings.TrimSpace(body.Note),
			Source:   "canary",
			RouteID:  routeID,
		})
		result["mode"] = "record_only"
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) getSMTPConfig(w http.ResponseWriter, r *http.Request) {
	if s.st == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"store unavailable"})
		return
	}
	cfg, err := s.st.GetSMTPConfig()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) putSMTPConfig(w http.ResponseWriter, r *http.Request) {
	if s.st == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"store unavailable"})
		return
	}
	var body struct {
		store.SMTPConfig
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.SaveSMTPConfig(body.SMTPConfig, body.Password); err != nil {
		s.writeErr(w, err)
		return
	}
	s.reloadMailer()
	cfg, _ := s.st.GetSMTPConfig()
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) postSMTPTest(w http.ResponseWriter, r *http.Request) {
	s.reloadMailer()
	if s.mailer == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"mailer unavailable"})
		return
	}
	if err := s.mailer.SendTest(""); err != nil {
		// Dial/auth failures are uncontrolled I/O text (host, path, etc.).
		// Route through writeErr so unknowns become fixed "internal error".
		s.writeErr(w, err)
		return
	}
	if s.security != nil {
		s.security.Record(security.Finding{
			Severity: security.SeverityInfo,
			Category: "smtp_test",
			Summary:  "SMTP 测试邮件已发送",
			Source:   "smtp_test",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

func (s *Server) reloadMailer() {
	if s.mailer == nil || s.st == nil {
		return
	}
	cfg, err := s.st.GetSMTPConfig()
	if err != nil {
		return
	}
	pw, _ := s.st.SMTPPasswordDecrypt()
	recips := strings.Split(cfg.Recipients, ",")
	clean := make([]string, 0, len(recips))
	for _, r := range recips {
		r = strings.TrimSpace(r)
		if r != "" {
			clean = append(clean, r)
		}
	}
	port := cfg.Port
	if port == 0 {
		port = 587
	}
	s.mailer.SetConfig(security.MailConfig{
		Enabled:     cfg.Enabled,
		Host:        cfg.Host,
		Port:        port,
		UseSTARTTLS: cfg.UseSTARTTLS,
		UseSMTPS:    cfg.UseSMTPS,
		From:        cfg.From,
		Recipients:  clean,
		Username:    cfg.Username,
		Password:    pw,
		MinSeverity: security.Severity(cfg.MinSeverity),
	})
	_ = strconv.Itoa(port)
}
