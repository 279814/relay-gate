package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	if m != nil && s.st != nil {
		m.SetIgnorePolicy(func(f security.Finding, atMS int64) (bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return s.st.SecurityFindingIgnored(ctx, f, atMS)
		})
	}
	if err := s.reloadMailer(); err != nil {
		s.log.Error("SMTP 配置未加载，邮件告警保持停用")
	}
	return s
}

func (s *Server) listSecurityFindings(w http.ResponseWriter, r *http.Request) {
	filter, err := securityFindingFilter(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if s.st != nil {
		page, err := s.st.ListSecurityFindingsPage(r.Context(), filter)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		keys, ok := s.diagnosticKeys(w, r)
		if !ok {
			return
		}
		page.Findings = redactFindingsForAPI(page.Findings, keys)
		writeJSON(w, http.StatusOK, page)
		return
	}
	// Preserve the limited ring-only diagnostic adapter, but never silently
	// ignore a filter or cursor that requires the durable authority.
	if filter.UpstreamID != 0 || filter.RouteID != 0 || filter.RuleID != "" || filter.ReviewStatus != "" || filter.Ignored != nil || filter.Category != "" || filter.FromMS != 0 || filter.ToMS != 0 || filter.Cursor != "" {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"persistent security findings unavailable"})
		return
	}
	if s.security == nil {
		writeJSON(w, http.StatusOK, map[string]any{"findings": []any{}, "total": 0})
		return
	}
	list := s.security.List(filter.Severity, filter.Limit)
	keys, ok := s.diagnosticKeys(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": redactFindingsForAPI(list, keys),
		"total":    s.security.Count(),
	})
}

func securityFindingFilter(r *http.Request) (store.SecurityFindingFilter, error) {
	var f store.SecurityFindingFilter
	q := r.URL.Query()
	for key, values := range q {
		switch key {
		case "severity", "upstream_id", "route_id", "rule_id", "review_status", "ignored", "category", "from_ms", "to_ms", "limit", "cursor":
		default:
			return f, model.WrapValidation("未知的安全发现筛选字段")
		}
		if len(values) != 1 {
			return f, model.WrapValidation("安全发现筛选字段不可重复")
		}
	}
	f.Severity = security.Severity(q.Get("severity"))
	f.Category = q.Get("category")
	f.RuleID = q.Get("rule_id")
	f.ReviewStatus = q.Get("review_status")
	var err error
	f.Ignored, err = securityBooleanFilter(q.Get("ignored"))
	if err != nil {
		return f, err
	}
	f.Cursor = q.Get("cursor")
	if len(f.Cursor) > 4096 {
		return f, model.WrapValidation("安全发现游标无效")
	}
	for _, item := range []struct {
		name   string
		target *int64
	}{{"upstream_id", &f.UpstreamID}, {"route_id", &f.RouteID}, {"from_ms", &f.FromMS}, {"to_ms", &f.ToMS}} {
		n, err := queryInt64(q.Get(item.name))
		if err != nil {
			return f, model.WrapValidation("安全发现数字筛选无效")
		}
		*item.target = n
	}
	limit, err := queryInt64(q.Get("limit"))
	if err != nil || limit < 0 || limit > store.MaximumPageLimit {
		return f, model.WrapValidation("安全发现分页大小无效")
	}
	f.Limit, err = store.NormalizePageLimit(int(limit))
	if err != nil {
		return f, err
	}
	return f, f.Validate()
}

// redactFindingsForAPI masks known upstream credentials in free-text finding
// fields before JSON encode (§2.4). ScanText already redacts on write; this
// is the read-path backstop for legacy plaintext Detail rows.
func redactFindingsForAPI(list []security.Finding, keys []string) []security.Finding {
	if len(keys) == 0 || len(list) == 0 {
		return list
	}
	out := make([]security.Finding, len(list))
	for i, f := range list {
		out[i] = security.RedactFindingForRead(f, keys)
	}
	return out
}

// maxFindingClientField caps free-text client strings written onto findings
// (admin scan req_id; canary note → Detail). decodeJSON allows up to 1MiB.
const maxFindingClientField = 256

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
	// Resolve upstream once: only a DB name/id may be stored on findings, and
	// only a resolved row supplies an API key for ScanText redaction. Unknown
	// / empty refs leave Upstream empty — never persist the raw client string
	// (it can be nearly the whole 1MiB body).
	upstream, lookupErr := s.resolveUpstreamForScan(r.Context(), body.Upstream)
	if lookupErr != nil {
		// No raw text may become a finding when the selected site's known
		// credential cannot be read. Do not log the input or driver error.
		writeJSON(w, http.StatusServiceUnavailable, errBody{"上游凭据暂不可读，请修复后重试"})
		return
	}
	var keys []string
	if upstream != nil && upstream.APIKey != "" {
		keys = append(keys, upstream.APIKey)
	}
	reqID := body.ReqID
	if len(reqID) > maxFindingClientField {
		reqID = reqID[:maxFindingClientField]
	}
	found := security.ScanText(body.Text, "admin_scan", keys...)
	out := make([]security.Finding, 0, len(found))
	for _, f := range found {
		if upstream != nil {
			f.Upstream = upstreamScanLabel(upstream)
			f.UpstreamID = upstream.ID
		}
		f.ReqID = reqID
		f.Source = "admin_scan" // caller-provided ReqID is never a trusted raw-sample relation
		f.ScannerVersion = security.ScannerVersion
		f.RuleVersion = security.RuleVersion
		f.BytesScanned = int64(len(body.Text))
		out = append(out, s.security.Record(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out, "count": len(out)})
}

// resolveUpstreamForScan returns only a canonical stored identity and credential.
// Empty/unknown refs return nil; a credential read failure rejects the scan.
func (s *Server) resolveUpstreamForScan(ctx context.Context, ref string) (*model.Upstream, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || s.st == nil {
		return nil, nil
	}
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil && id > 0 {
		up, err := s.configAdmin.GetUpstream(ctx, id)
		if err == nil {
			return &up, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	up, err := s.configAdmin.GetUpstreamByName(ctx, ref)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &up, nil
}

func upstreamScanLabel(up *model.Upstream) string {
	if up == nil {
		return ""
	}
	if name := strings.TrimSpace(up.Name); name != "" {
		return name
	}
	return strconv.FormatInt(up.ID, 10)
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
		ExpectedRevision     *int64 `json:"expected_revision"`
		Enabled              bool   `json:"enabled"`
		Host                 string `json:"host"`
		Port                 int    `json:"port"`
		UseSTARTTLS          bool   `json:"use_starttls"`
		UseSMTPS             bool   `json:"use_smtps"`
		From                 string `json:"from"`
		Recipients           string `json:"recipients"`
		Username             string `json:"username"`
		MinSeverity          string `json:"min_severity"`
		AggregationWindowSec *int   `json:"aggregation_window_sec"`
		RateLimitWindowSec   *int   `json:"rate_limit_window_sec"`
		Password             string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.ExpectedRevision == nil || *body.ExpectedRevision < 1 {
		s.writeErr(w, fmt.Errorf("%w: expected_revision 必须为正整数", model.ErrValidation))
		return
	}
	current, err := s.st.GetSMTPConfig()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	cfg := store.SMTPConfig{
		Enabled: body.Enabled, Host: body.Host, Port: body.Port, UseSTARTTLS: body.UseSTARTTLS, UseSMTPS: body.UseSMTPS,
		From: body.From, Recipients: body.Recipients, Username: body.Username, MinSeverity: body.MinSeverity,
		Revision: *body.ExpectedRevision, AggregationWindowSec: current.AggregationWindowSec, RateLimitWindowSec: current.RateLimitWindowSec,
	}
	if body.AggregationWindowSec != nil {
		cfg.AggregationWindowSec = *body.AggregationWindowSec
	}
	if body.RateLimitWindowSec != nil {
		cfg.RateLimitWindowSec = *body.RateLimitWindowSec
	}
	if err := s.st.SaveSMTPConfig(cfg, body.Password); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.reloadMailer(); err != nil {
		// The mutation committed. Keep its success distinct from activation so a
		// client never retries the password/configuration mutation blindly.
		writeJSON(w, http.StatusOK, map[string]any{"persisted": true, "config_activation_pending": true})
		return
	}
	cfg, err = s.st.GetSMTPConfig()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"persisted": true, "config_activation_pending": true})
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) postSMTPTest(w http.ResponseWriter, r *http.Request) {
	if err := s.reloadMailer(); err != nil {
		s.writeErr(w, err)
		return
	}
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

func (s *Server) reloadMailer() error {
	if s.mailer == nil || s.st == nil {
		return nil
	}
	cfg, err := s.st.SMTPMailerConfig()
	if err != nil {
		return err
	}
	return s.mailer.SetConfig(cfg)
}
