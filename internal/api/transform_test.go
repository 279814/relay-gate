package api

import (
	"bytes"
	"encoding/json"
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

func itoa64(v int64) string {
	return jsonNumber(v)
}

func jsonNumber(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
