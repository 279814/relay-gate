package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func TestAuditHistoryEndpointPersistsAndRequiresAdmin(t *testing.T) {
	s, h := newTestServer(t)
	id, err := s.st.BeginAuditEvent(context.Background(), "route_disable", "42", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.st.CompleteAuditEvent(context.Background(), id, "failed", "conflict"); err != nil {
		t.Fatal(err)
	}
	path := "/admin/api/audit-events?category=route&action=route_disable&outcome=failed&resource_type=route&resource_id=42&limit=1"
	if response := do(t, h, "GET", path, "", false); response.Code != http.StatusUnauthorized {
		t.Fatalf("audit history allowed unauthenticated read: %d", response.Code)
	}
	response := do(t, h, "GET", path, "", true)
	if response.Code != http.StatusOK {
		t.Fatalf("audit history unavailable: status=%d body=%s", response.Code, response.Body.String())
	}
	page := decodeBody[model.Page[*model.AuditEvent]](t, response)
	if len(page.Items) != 1 || page.Items[0].ID != id || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("audit page=%+v headers=%v", page, response.Header())
	}
	databasePath := s.st.DatabasePath()
	s.st.Close()
	cipher, _ := store.NewCipher("test-passphrase-at-least-16-chars")
	reopened, err := store.Open(databasePath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next := New(reopened, s.log).Routes(testAdminPW)
	response = do(t, next, "GET", path, "", true)
	page = decodeBody[model.Page[*model.AuditEvent]](t, response)
	if response.Code != http.StatusOK || len(page.Items) != 1 || page.Items[0].ID != id {
		t.Fatalf("restart lost audit history: status=%d page=%+v", response.Code, page)
	}
}

type auditCountingWriter struct {
	header      http.Header
	status      int
	bytes       int
	payloadSeen bool
	beforeWrite func()
}

func (w *auditCountingWriter) Header() http.Header    { return w.header }
func (w *auditCountingWriter) WriteHeader(status int) { w.status = status }
func (w *auditCountingWriter) Write(value []byte) (int, error) {
	if w.beforeWrite != nil {
		w.beforeWrite()
		w.beforeWrite = nil
	}
	w.bytes += len(value)
	w.payloadSeen = w.payloadSeen || bytes.Contains(value, []byte("private-large-sample"))
	return len(value), nil
}

func TestLargeSensitiveAuditStreamsWithoutAnotherBodyBufferAndFailsBeforePlaintext(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "stream", true: "reject"}[reject], func(t *testing.T) {
			s, _ := newTestServer(t)
			if reject {
				if _, err := s.st.DB().Exec(`CREATE TRIGGER deny_large_view_audit BEFORE UPDATE OF outcome ON audit_event WHEN NEW.action='sample_view' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			}
			writer := &auditCountingWriter{header: make(http.Header)}
			writer.beforeWrite = func() {
				var outcome string
				if err := s.st.DB().QueryRow(`SELECT outcome FROM audit_event WHERE action='sample_view'`).Scan(&outcome); err != nil {
					t.Fatal(err)
				}
				if !reject && outcome != "succeeded" {
					t.Fatal("first plaintext byte preceded its durable audit completion")
				}
			}
			chunk := bytes.Repeat([]byte("private-large-sample"), 4096)
			handler := s.requireAdmin(s.auditAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for n := 0; n < 64; n++ {
					_, err := w.Write(chunk)
					if reject {
						if err == nil {
							t.Fatal("a blocked plaintext write was reported as delivered")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if n == 0 && !reject && writer.bytes != len(chunk) {
						t.Fatal("audit added buffering before sending the first body chunk")
					}
				}
			})))
			request := httptest.NewRequest("POST", "/admin/api/samples/42/view", nil)
			request.Header.Set("Authorization", "Bearer "+testAdminPW)
			handler.ServeHTTP(writer, request)
			if reject {
				if writer.status != http.StatusServiceUnavailable || writer.payloadSeen || writer.bytes > 1024 {
					t.Fatalf("large sample escaped its failed audit: status=%d bytes=%d plaintext=%t", writer.status, writer.bytes, writer.payloadSeen)
				}
			} else if writer.bytes != len(chunk)*64 || !writer.payloadSeen {
				t.Fatal("auditing changed the streamed sample bytes")
			}
		})
	}
}

func TestSensitiveRevealNeverReturnsPlaintextWithoutDurableAudit(t *testing.T) {
	for _, failure := range []string{"begin", "complete"} {
		t.Run(failure, func(t *testing.T) {
			s, h := newTestServer(t)
			cipher, _ := store.NewCipher("audit-reveal-envelope-key-long-enough")
			creds := credential.New().WithEnvelope(cipher)
			const raw = "rk-audit-sensitive-reveal-fixture"
			if err := creds.SetActiveRelayKey(raw); err != nil {
				t.Fatal(err)
			}
			s.WithCredentials(creds, nil)
			session := loginSession(t, h)
			trigger := `CREATE TRIGGER deny_reveal_audit BEFORE INSERT ON audit_event WHEN NEW.action='relay_reveal' BEGIN SELECT RAISE(ABORT,'reveal audit unavailable'); END`
			if failure == "complete" {
				trigger = `CREATE TRIGGER deny_reveal_audit BEFORE UPDATE OF outcome ON audit_event WHEN NEW.action='relay_reveal' BEGIN SELECT RAISE(ABORT,'reveal audit unavailable'); END`
			}
			if _, err := s.st.DB().Exec(trigger); err != nil {
				t.Fatal(err)
			}
			response := doSession(t, h, "POST", "/admin/api/credentials/reveal-relay", `{"password":"`+testAdminPW+`"}`, session)
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), raw) || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("failed audit leaked sensitive reveal: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestRelayRotationCompletedBeforeAuditFailureIsNotReportedRetryable(t *testing.T) {
	s, h := newTestServer(t)
	creds := credential.New()
	const old = "rk-audit-rotation-old-fixture"
	if err := creds.SetActiveRelayKey(old); err != nil {
		t.Fatal(err)
	}
	s.WithCredentials(creds, nil)
	session := loginSession(t, h)
	if _, err := s.st.DB().Exec(`CREATE TRIGGER deny_rotation_audit_finish BEFORE UPDATE OF outcome ON audit_event WHEN NEW.action='relay_rotate' BEGIN SELECT RAISE(ABORT,'terminal audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	response := doSession(t, h, "POST", "/admin/api/credentials/rotate-relay", `{"password":"`+testAdminPW+`"}`, session)
	if response.Code != http.StatusOK || response.Header().Get("X-Audit-Status") != "pending" || response.Header().Get("X-Audit-Event-ID") == "" {
		t.Fatalf("completed rotation appeared failed or hid pending audit: status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var result struct {
		RelayKey string `json:"relay_key"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.RelayKey == "" || result.RelayKey == old || !creds.ValidRelayKey(result.RelayKey) {
		t.Fatal("completed rotation did not return its active key", err)
	}
	var outcome string
	if err := s.st.DB().QueryRow(`SELECT outcome FROM audit_event WHERE action='relay_rotate'`).Scan(&outcome); err != nil || outcome != "pending" {
		t.Fatalf("failed terminal audit was claimed durable: outcome=%s err=%v", outcome, err)
	}
}

func latestAudit(t *testing.T, s *Server, action, outcome string) *model.AuditEvent {
	t.Helper()
	page, err := s.st.ListAuditEventsPage(context.Background(), model.AuditEventFilter{PageRequest: model.PageRequest{Limit: 1}, Action: action})
	if err != nil || len(page.Items) != 1 || page.Items[0].Outcome != outcome {
		t.Fatalf("missing truthful %s/%s audit: page=%+v err=%v", action, outcome, page, err)
	}
	return page.Items[0]
}

func TestManualRouteDisableAuditsCASFailureAndBlocksUnauditableMutation(t *testing.T) {
	s, h := newTestServer(t)
	up := &model.Upstream{Name: "audit-route", BaseURL: "https://audit.example.invalid", APIKey: "private-audit-route-fixture-key", Enabled: true}
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	mn := &model.ModelName{Name: "audit-route-model", Protocol: model.ProtoAnthropic, Enabled: true}
	if err := s.st.CreateModelName(mn); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true}
	if err := s.st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	path := "/admin/api/routes/" + itoa(route.ID)
	if _, err := s.st.DB().Exec(`CREATE TRIGGER deny_route_audit BEFORE INSERT ON audit_event WHEN NEW.action='route_update' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	response := do(t, h, "PUT", path, `{"expected_revision":1,"enabled":false}`, true)
	current, err := s.st.GetRoute(route.ID)
	if response.Code != http.StatusServiceUnavailable || err != nil || !current.Enabled || current.Revision != 1 {
		t.Fatal("route changed without a durable audit attempt", err)
	}
	if _, err := s.st.DB().Exec(`DROP TRIGGER deny_route_audit`); err != nil {
		t.Fatal(err)
	}
	response = do(t, h, "PUT", path, `{"expected_revision":999,"enabled":false}`, true)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale disable bypassed CAS: %d", response.Code)
	}
	failed := latestAudit(t, s, "route_disable", "failed")
	if failed.ResourceID != itoa(route.ID) || failed.ReasonCode != "conflict" {
		t.Fatalf("route failure lost resource or reason: %+v", failed)
	}
	response = do(t, h, "PUT", path, `{"expected_revision":1,"enabled":false}`, true)
	if response.Code != http.StatusOK {
		t.Fatalf("audited disable failed: %d %s", response.Code, response.Body.String())
	}
	latestAudit(t, s, "route_disable", "succeeded")
	response = do(t, h, "PUT", path, `{"expected_revision":1,"enabled":false}`, true)
	if response.Code != http.StatusConflict {
		t.Fatalf("repeated stale disable bypassed CAS: %d", response.Code)
	}
	latestAudit(t, s, "route_disable", "failed")
	page := do(t, h, "GET", "/admin/api/audit-events?resource_type=route", "", true)
	for _, secret := range []string{up.APIKey, testAdminPW, "audit unavailable"} {
		if strings.Contains(page.Body.String(), secret) {
			t.Fatal("audit persisted credential or raw error text")
		}
	}
}
