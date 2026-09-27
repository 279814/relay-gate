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
func sampleAuditActions(t *testing.T, h http.Handler) []credential.AuditEvent {
	t.Helper()
	rec := do(t, h, "GET", "/admin/api/credentials", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("credentials status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Audit []credential.AuditEvent `json:"audit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	var got []credential.AuditEvent
	for _, ev := range out.Audit {
		if strings.HasPrefix(ev.Action, "sample_") {
			got = append(got, ev)
		}
	}
	return got
}

// TestSampleActions_WriteAuditOnSuccessOnly covers §5.4: viewing, pinning and
// bulk-deleting unredacted samples write an audit record on success; failed
// re-auth writes none, and the record never carries the sample body.
func TestSampleActions_WriteAuditOnSuccessOnly(t *testing.T) {
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
	if rec := do(t, h, "POST", "/admin/api/samples/"+id+"/pin", `{"pinned":true,"password":"not-the-admin"}`, true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("pin wrong password want 401, got %d", rec.Code)
	}
	if rec := do(t, h, "DELETE", "/admin/api/samples", badPW, true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("clear wrong password want 401, got %d", rec.Code)
	}
	if got := sampleAuditActions(t, h); len(got) != 0 {
		t.Fatalf("failed re-auth must not write audit, got %+v", got)
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
	want := []struct{ action, detail string }{
		{"sample_bulk_delete", "deleted=1 keep_pinned=false"},
		{"sample_pin", "id=" + id + " pinned=true"},
		{"sample_view", "id=" + id},
	}
	if len(got) != len(want) {
		t.Fatalf("audit rows=%+v, want %d sample rows", got, len(want))
	}
	for i, w := range want {
		if got[i].Action != w.action || got[i].Detail != w.detail {
			t.Fatalf("audit[%d]=%+v, want action=%q detail=%q", i, got[i], w.action, w.detail)
		}
		if strings.Contains(got[i].Detail, secret) || strings.Contains(got[i].Detail, testAdminPW) {
			t.Fatalf("audit[%d] leaks body or password: %+v", i, got[i])
		}
	}
}
