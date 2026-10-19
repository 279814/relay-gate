package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
	"strings"
)

func TestTransformAdminDraftCASAndTerminalArchive(t *testing.T) {
	s, _ := newTestServer(t)
	registry := transform.NewRegistry(20).WithPersist(s.st)
	h := s.WithTransformRegistry(registry).Routes(testAdminPW)
	created := do(t, h, "POST", "/admin/api/transforms", `{"name":"versioned transform"}`, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	var set struct {
		ID       int64  `json:"id"`
		Revision int64  `json:"revision"`
		State    string `json:"state"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if set.Revision != 1 || set.State != "active" {
		t.Fatalf("missing initial state/revision: %+v", set)
	}
	path := fmt.Sprintf("/admin/api/transforms/%d", set.ID)
	draft := `{"expected_revision":1,"rules":[{"kind":"set_header","name":"X-Saved","value":"original"}],"note":"saved"}`
	rec := do(t, h, "PUT", path+"/draft", draft, true)
	if rec.Code != 200 {
		t.Fatalf("save draft=%d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if set.Revision != 2 {
		t.Fatalf("saved revision=%d", set.Revision)
	}
	rec = do(t, h, "PUT", path+"/draft", draft, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale draft=%d %s", rec.Code, rec.Body.String())
	}
	for _, body := range []string{`{"rules":[]}`, `{"expected_revision":0,"rules":[]}`} {
		if bad := do(t, h, "PUT", path+"/draft", body, true); bad.Code != 400 {
			t.Fatalf("missing/invalid expected revision=%d", bad.Code)
		}
	}
	rec = do(t, h, "POST", path+"/disable", `{"expected_revision":2}`, true)
	if rec.Code != 200 {
		t.Fatalf("disable=%d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if set.State != "disabled" || set.Revision != 3 {
		t.Fatalf("disabled=%+v", set)
	}
	rec = do(t, h, "POST", path+"/archive", `{"expected_revision":3}`, true)
	if rec.Code != 200 {
		t.Fatalf("archive=%d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if set.State != "archived" || set.Revision != 4 {
		t.Fatalf("archived=%+v", set)
	}
	rec = do(t, h, "POST", path+"/enable", `{"expected_revision":4}`, true)
	if rec.Code != 400 {
		t.Fatalf("archived enable=%d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, "PUT", path+"/draft", `{"expected_revision":4,"rules":[]}`, true)
	if rec.Code != 400 {
		t.Fatalf("archived edit=%d %s", rec.Code, rec.Body.String())
	}
	restarted := transform.NewRegistry(20).WithPersist(s.st)
	if err := restarted.LoadFromPersist(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := restarted.GetSet(set.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(snapshot)
	if err := json.Unmarshal(encoded, &set); err != nil {
		t.Fatal(err)
	}
	if set.State != "archived" || set.Revision != 4 {
		t.Fatal("restart lost lifecycle or revision")
	}
}

func TestTransformBudgetsCASConfirmationAndRestart(t *testing.T) {
	s, _ := newTestServer(t)
	registry := transform.NewRegistry(8).WithPersist(s.st)
	if err := registry.LoadFromPersist(); err != nil {
		t.Fatal(err)
	}
	h := s.WithTransformRegistry(registry).Routes(testAdminPW)
	read := do(t, h, "GET", "/admin/api/transforms/budgets", "", true)
	var state struct {
		Revision int64                  `json:"revision"`
		Budgets  transform.BudgetLimits `json:"budgets"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if read.Code != 200 || state.Revision != 1 || state.Budgets.RequestMs != 50 {
		t.Fatalf("budget defaults=%d %+v", read.Code, state)
	}
	denied := do(t, h, "PUT", "/admin/api/transforms/budgets", `{"expected_revision":1,"request_ms":80,"sse_event_ms":20,"confirm_raise":false}`, true)
	if denied.Code != 400 || registry.Budgets().RequestMs != 50 {
		t.Fatal("unconfirmed raise changed budgets")
	}
	saved := do(t, h, "PUT", "/admin/api/transforms/budgets", `{"expected_revision":1,"request_ms":80,"sse_event_ms":20,"confirm_raise":true}`, true)
	if saved.Code != 200 {
		t.Fatalf("budget save=%d %s", saved.Code, saved.Body.String())
	}
	if err := json.Unmarshal(saved.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Revision != 2 {
		t.Fatalf("budget revision=%d", state.Revision)
	}
	stale := do(t, h, "PUT", "/admin/api/transforms/budgets", `{"expected_revision":1,"request_ms":40,"sse_event_ms":10}`, true)
	if stale.Code != 409 {
		t.Fatalf("stale budget=%d %s", stale.Code, stale.Body.String())
	}
	restarted := transform.NewRegistry(8).WithPersist(s.st)
	if err := restarted.LoadFromPersist(); err != nil {
		t.Fatal(err)
	}
	if got := restarted.Budgets(); got.RequestMs != 80 || got.SSEEventMs != 20 {
		t.Fatalf("restart lost budgets: %+v", got)
	}
	latest := do(t, h, "GET", "/admin/api/transforms/budgets", "", true)
	if err := json.Unmarshal(latest.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Revision != 2 {
		t.Fatal("conflict changed persisted budget revision")
	}
}

func TestTransformPreviewOmitsKnownCredentialHashesWithoutResolvingReferences(t *testing.T) {
	s, _ := newTestServer(t)
	const credential = "fixture-preview-credential-48c9d"
	up := &model.Upstream{Name: "preview-redaction", BaseURL: "https://preview.example.test", APIKey: credential}
	up.Defaults()
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	registry := transform.NewRegistry(8).WithPersist(s.st)
	set, err := registry.CreateSet("redacted preview")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindReplaceBytes, From: "unchanged", To: "changed"}}, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	h := s.WithTransformRegistry(registry).Routes(testAdminPW)
	body, _ := json.Marshal(map[string]any{"phase": "request", "body": credential})
	result := do(t, h, "POST", fmt.Sprintf("/admin/api/transforms/%d/preview", set.ID), string(body), true)
	if result.Code != 200 {
		t.Fatalf("preview=%d %s", result.Code, result.Body.String())
	}
	if strings.Contains(result.Body.String(), credential) || strings.Contains(result.Body.String(), transform.HashBytes([]byte(credential))) {
		t.Fatal("preview leaked known credential or its hash")
	}
	if !strings.Contains(result.Body.String(), "omitted(secret_taint)") {
		t.Fatal("preview did not explain omitted hashes")
	}
	for _, record := range registry.ListExecutions(10) {
		if record.InputHash != "" || record.OutputHash != "" {
			t.Fatal("secret preview retained a hash")
		}
	}
}
