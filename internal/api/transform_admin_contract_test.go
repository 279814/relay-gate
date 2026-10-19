package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
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
