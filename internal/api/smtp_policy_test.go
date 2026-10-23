package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/security"
)

func TestSMTPCASRejectsStaleAndInvalidWithoutPublishing(t *testing.T) {
	s, _ := newTestServer(t)
	mailer := security.NewAlertMailer()
	h := s.WithAlertMailer(mailer).Routes(testAdminPW)
	first := `{"expected_revision":1,"enabled":true,"host":"smtp.example.test","port":587,"use_starttls":true,"from":"relay@example.test","recipients":"ops@example.test","min_severity":"critical","password":"fixture-smtp-existing","aggregation_window_sec":7,"rate_limit_window_sec":13}`
	saved := do(t, h, "PUT", "/admin/api/security/smtp", first, true)
	if saved.Code != http.StatusOK {
		t.Fatalf("initial SMTP save=%d %s", saved.Code, saved.Body.String())
	}
	var config struct {
		Revision    int64 `json:"revision"`
		Aggregation int   `json:"aggregation_window_sec"`
		Rate        int   `json:"rate_limit_window_sec"`
	}
	if err := json.Unmarshal(saved.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if config.Revision != 2 || config.Aggregation != 7 || config.Rate != 13 {
		t.Fatalf("saved SMTP policy=%+v", config)
	}
	if strings.Contains(saved.Body.String(), "fixture-smtp-existing") {
		t.Fatal("password returned")
	}
	original := mailer.Config()
	rejected := do(t, h, "PUT", "/admin/api/security/smtp", strings.ReplaceAll(first, "smtp.example.test", "stale.example.test"), true)
	if rejected.Code != http.StatusConflict {
		t.Fatalf("stale SMTP save=%d %s", rejected.Code, rejected.Body.String())
	}
	if mailer.Config().Host != original.Host {
		t.Fatal("stale SMTP config published")
	}
	for _, bad := range []string{
		strings.Replace(first, `"expected_revision":1,`, "", 1),
		strings.Replace(first, `"expected_revision":1`, `"expected_revision":0`, 1),
		strings.Replace(strings.Replace(first, `"expected_revision":1`, `"expected_revision":2`, 1), `"aggregation_window_sec":7`, `"aggregation_window_sec":0`, 1),
		strings.Replace(strings.Replace(first, `"expected_revision":1`, `"expected_revision":2`, 1), `"rate_limit_window_sec":13`, `"rate_limit_window_sec":86401`, 1),
	} {
		rec := do(t, h, "PUT", "/admin/api/security/smtp", bad, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid SMTP save=%d %s", rec.Code, rec.Body.String())
		}
	}
	current, err := s.st.GetSMTPConfig()
	if err != nil || current.Host != original.Host {
		t.Fatalf("SMTP persisted state changed: %v", err)
	}
	password, err := s.st.SMTPPasswordDecrypt()
	if err != nil || password != "fixture-smtp-existing" {
		t.Fatal("rejected SMTP save changed password")
	}
	// Missing new windows preserves saved values, rather than silently resetting.
	update := do(t, h, "PUT", "/admin/api/security/smtp", `{"expected_revision":2,"enabled":true,"host":"smtp-new.example.test","port":587,"use_starttls":true,"from":"relay@example.test","recipients":"ops@example.test","min_severity":"critical"}`, true)
	if update.Code != http.StatusOK {
		t.Fatalf("valid update=%d %s", update.Code, update.Body.String())
	}
	if err := json.Unmarshal(update.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if config.Revision != 3 || config.Aggregation != 7 || config.Rate != 13 || mailer.Config().Host != "smtp-new.example.test" {
		t.Fatal("updated policy not published after commit")
	}
}

func TestSMTPMailerStartsFromSavedPolicyAndFailedSaveNeverPublishes(t *testing.T) {
	s, _ := newTestServer(t)
	cfg, err := s.st.GetSMTPConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Enabled = true
	cfg.Host = "smtp.example.test"
	cfg.UseSTARTTLS = true
	cfg.From = "relay@example.test"
	cfg.Recipients = "ops@example.test"
	cfg.AggregationWindowSec = 7
	cfg.RateLimitWindowSec = 13
	if err := s.st.SaveSMTPConfig(cfg, "fixture-startup-password"); err != nil {
		t.Fatal(err)
	}
	mailer := security.NewAlertMailer()
	h := s.WithAlertMailer(mailer).Routes(testAdminPW)
	live := mailer.Config()
	if !live.Enabled || live.Revision != 2 || live.AggregationWindowSec != 7 || live.RateLimitWindowSec != 13 {
		t.Fatalf("saved mailer not restored: %+v", live)
	}
	if _, err := s.st.DB().Exec(`CREATE TRIGGER reject_smtp BEFORE UPDATE ON smtp_config BEGIN SELECT RAISE(ABORT,'fixture update denied'); END`); err != nil {
		t.Fatal(err)
	}
	result := do(t, h, "PUT", "/admin/api/security/smtp", `{"expected_revision":2,"enabled":false,"host":"new.example.test","aggregation_window_sec":19,"rate_limit_window_sec":29,"password":"fixture-replacement"}`, true)
	if result.Code != http.StatusInternalServerError {
		t.Fatalf("failed write=%d %s", result.Code, result.Body.String())
	}
	if current := mailer.Config(); current.Host != live.Host || !current.Enabled || current.Revision != 2 {
		t.Fatal("failed DB write changed live mailer")
	}
	saved, err := s.st.GetSMTPConfig()
	if err != nil || saved.Revision != 2 || saved.AggregationWindowSec != 7 {
		t.Fatal("failed DB write changed saved policy")
	}
	password, err := s.st.SMTPPasswordDecrypt()
	if err != nil || password != "fixture-startup-password" {
		t.Fatal("failed DB write changed password")
	}
}
