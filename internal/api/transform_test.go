package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

func TestTransformAPI_PublishPreview(t *testing.T) {
	reg := transform.NewRegistry(20)
	s := New(nil, nil).WithTransformRegistry(reg)
	h := s.Routes("pw")

	create := httptest.NewRequest(http.MethodPost, "/admin/api/transforms", bytes.NewReader([]byte(`{"name":"t1"}`)))
	create.Header.Set("Authorization", "Bearer pw")
	create.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, create)
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", w.Code, w.Body.String())
	}
	var set transform.Set
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}

	draftBody := `{"rules":[{"kind":"replace_bytes","from":"A","to":"B"}],"note":"n1"}`
	put := httptest.NewRequest(http.MethodPut, "/admin/api/transforms/"+itoa64(set.ID)+"/draft", bytes.NewReader([]byte(draftBody)))
	put.Header.Set("Authorization", "Bearer pw")
	put.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, put)
	if w.Code != http.StatusOK {
		t.Fatalf("draft=%d %s", w.Code, w.Body.String())
	}

	prev := httptest.NewRequest(http.MethodPost, "/admin/api/transforms/"+itoa64(set.ID)+"/preview",
		bytes.NewReader([]byte(`{"phase":"request","body":"A"}`)))
	prev.Header.Set("Authorization", "Bearer pw")
	prev.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, prev)
	if w.Code != http.StatusOK {
		t.Fatalf("preview=%d %s", w.Code, w.Body.String())
	}
}

func TestTransformAPI_PublishRollback(t *testing.T) {
	reg := transform.NewRegistry(20)
	s := New(nil, nil).WithTransformRegistry(reg)
	h := s.Routes("pw")

	create := httptest.NewRequest(http.MethodPost, "/admin/api/transforms", bytes.NewReader([]byte(`{"name":"rb"}`)))
	create.Header.Set("Authorization", "Bearer pw")
	create.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, create)
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", w.Code, w.Body.String())
	}
	var set transform.Set
	_ = json.Unmarshal(w.Body.Bytes(), &set)

	putDraft := func(from, to string) {
		body := fmt.Sprintf(`{"rules":[{"kind":"replace_bytes","from":%q,"to":%q}]}`, from, to)
		req := httptest.NewRequest(http.MethodPut, "/admin/api/transforms/"+itoa64(set.ID)+"/draft", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer pw")
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("draft=%d %s", w.Code, w.Body.String())
		}
	}
	publish := func() (transform.Binding, transform.Version) {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/transforms/"+itoa64(set.ID)+"/publish",
			bytes.NewReader([]byte(`{"route_id":1,"endpoint_id":2}`)))
		req.Header.Set("Authorization", "Bearer pw")
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("publish=%d %s", w.Code, w.Body.String())
		}
		var out struct {
			Binding transform.Binding `json:"binding"`
			Version transform.Version `json:"version"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out.Binding, out.Version
	}

	putDraft("A", "B")
	_, v1 := publish()
	putDraft("A", "C")
	b2, _ := publish()
	if b2.PublishedID == v1.ID {
		t.Fatal("expected new published id")
	}

	rb := httptest.NewRequest(http.MethodPost, "/admin/api/transforms/rollback",
		bytes.NewReader([]byte(fmt.Sprintf(`{"route_id":1,"endpoint_id":2,"version_id":%d}`, v1.ID))))
	rb.Header.Set("Authorization", "Bearer pw")
	rb.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, rb)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback=%d %s", w.Code, w.Body.String())
	}
	var binding transform.Binding
	_ = json.Unmarshal(w.Body.Bytes(), &binding)
	if binding.PublishedID != v1.ID {
		t.Fatalf("published=%d want %d", binding.PublishedID, v1.ID)
	}
}

func TestTransformAPI_BudgetsRaiseRequiresConfirm(t *testing.T) {
	reg := transform.NewRegistry(20)
	s := New(nil, nil).WithTransformRegistry(reg)
	h := s.Routes("pw")

	raise := httptest.NewRequest(http.MethodPut, "/admin/api/transforms/budgets",
		bytes.NewReader([]byte(`{"request_ms":80,"sse_event_ms":10,"confirm_raise":false}`)))
	raise.Header.Set("Authorization", "Bearer pw")
	raise.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, raise)
	if w.Code == http.StatusOK {
		t.Fatalf("raise without confirm should fail: %s", w.Body.String())
	}

	ok := httptest.NewRequest(http.MethodPut, "/admin/api/transforms/budgets",
		bytes.NewReader([]byte(`{"request_ms":80,"sse_event_ms":10,"confirm_raise":true}`)))
	ok.Header.Set("Authorization", "Bearer pw")
	ok.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, ok)
	if w.Code != http.StatusOK {
		t.Fatalf("raise confirm=%d %s", w.Code, w.Body.String())
	}
	var body struct {
		Budgets transform.BudgetLimits  `json:"budgets"`
		Audit   []transform.BudgetAudit `json:"audit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Budgets.RequestMs != 80 || len(body.Audit) == 0 || body.Audit[0].Action != "raise_budget" {
		t.Fatalf("body=%+v", body)
	}
}

func itoa64(v int64) string {
	return jsonNumber(v)
}

func jsonNumber(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
