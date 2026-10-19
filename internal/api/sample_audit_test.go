package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/model"
)

// sampleAuditActions 从 GET /admin/api/credentials 的 audit 里取出 sample_* 记录（新的在前）。
func sampleAuditActions(t *testing.T, h http.Handler) []*model.AuditEvent {
	t.Helper()
	rec := do(t, h, "GET", "/admin/api/credentials", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("credentials status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Audit []*model.AuditEvent `json:"audit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	var got []*model.AuditEvent
	for _, ev := range out.Audit {
		if strings.HasPrefix(ev.Action, "sample_") {
			got = append(got, ev)
		}
	}
	return got
}

// Failed re-auth and completed sensitive operations share the durable history.
// Neither path may record the request password, sample body or free detail.
func TestSampleActionsPersistSuccessAndFailureWithoutSensitiveContent(t *testing.T) {
	s, h := newTestServer(t)
	s.WithCredentials(credential.New(), nil)

	const secret = "private-conversation-must-not-be-audited"
	smp := &model.Sample{
		ReqID:       "audit-sample",
		TSRecv:      time.Now().UnixMilli(),
		TSSent:      time.Now().UnixMilli(),
		TSDone:      time.Now().UnixMilli(),
		Endpoint:    "/v1/messages",
		InMethod:    "POST",
		InPath:      "/v1/messages",
		InHeaders:   http.Header{},
		InBody:      []byte(secret),
		OutHeaders:  http.Header{},
		OutBody:     []byte(`{"out":1}`),
		RespStatus:  200,
		RespHeaders: http.Header{},
		RespBody:    []byte(`{"resp":1}`),
		Outcome:     model.OutcomeOK,
	}
	if err := s.st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	id := itoa(smp.ID)
	badPW := `{"password":"not-the-admin"}`
	goodPW := `"password":"` + testAdminPW + `"`

	if rec := do(t, h, "GET", "/admin/api/samples/"+id, badPW, true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("view wrong password want 401, got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/admin/api/samples/"+id+"/pin", `{"pinned":true,"password":"not-the-admin"}`, true); rec.Code != http.StatusForbidden {
		t.Fatalf("pin wrong password want 403, got %d", rec.Code)
	}
	if rec := do(t, h, "DELETE", "/admin/api/samples", badPW, true); rec.Code != http.StatusForbidden {
		t.Fatalf("clear wrong password want 403, got %d", rec.Code)
	}
	if got := sampleAuditActions(t, h); len(got) != 3 {
		t.Fatalf("failed re-auth must be audited, got %+v", got)
	}

	if rec := do(t, h, "GET", "/admin/api/samples/"+id, "{"+goodPW+"}", true); rec.Code != http.StatusOK {
		t.Fatalf("view want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(t, h, "POST", "/admin/api/samples/"+id+"/pin", `{"pinned":true,`+goodPW+`}`, true); rec.Code != http.StatusOK {
		t.Fatalf("pin want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(t, h, "DELETE", "/admin/api/samples?keep_pinned=false", "{"+goodPW+"}", true); rec.Code != http.StatusOK {
		t.Fatalf("clear want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	got := sampleAuditActions(t, h)
	want := []struct{ action, outcome, resourceID string }{
		{"sample_bulk_delete", "succeeded", ""},
		{"sample_pin", "succeeded", id},
		{"sample_view", "succeeded", id},
		{"sample_bulk_delete", "failed", ""},
		{"sample_pin", "failed", id},
		{"sample_view", "failed", id},
	}
	if len(got) != len(want) {
		t.Fatalf("audit rows=%+v, want %d sample rows", got, len(want))
	}
	for i, w := range want {
		if got[i].Action != w.action || got[i].Outcome != w.outcome || got[i].ResourceID != w.resourceID {
			t.Fatalf("audit[%d]=%+v, want %+v", i, got[i], w)
		}
		encoded, _ := json.Marshal(got[i])
		if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), testAdminPW) {
			t.Fatalf("audit[%d] leaks body or password: %+v", i, got[i])
		}
	}
}
