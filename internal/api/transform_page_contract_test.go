package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

func TestTransformListsUseBoundedMetadataAndFilterBoundCursor(t *testing.T) {
	s, _ := newTestServer(t)
	tx, err := s.st.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	const privateDraft = `{"id":1,"revision":1,"note":"must-not-appear-in-metadata","rules":[]}`
	for i := 1; i <= 205; i++ {
		state := "active"
		if i == 1 {
			state = "disabled"
		}
		if _, err := tx.Exec(`INSERT INTO transform_set(id,name,created_at,draft_json,revision,lifecycle_state) VALUES(?,?,?,?,1,?)`, i, fmt.Sprintf("set-%03d", i), i, privateDraft, state); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	registry := transform.NewRegistry(8).WithPersist(s.st)
	if err := registry.LoadFromPersist(); err != nil {
		t.Fatal(err)
	}
	h := s.WithTransformRegistry(registry).Routes(testAdminPW)
	read := do(t, h, "GET", "/admin/api/transforms?state=active", "", true)
	if read.Code != 200 {
		t.Fatalf("sets=%d %s", read.Code, read.Body.String())
	}
	var page struct {
		Sets []struct {
			ID    int64           `json:"id"`
			Draft json.RawMessage `json:"draft"`
		} `json:"sets"`
		Total int64  `json:"total"`
		Next  string `json:"next_cursor"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Sets) != 50 || page.Total != 204 || page.Next == "" {
		t.Fatalf("unbounded/uncounted transform page: items=%d total=%d next=%t", len(page.Sets), page.Total, page.Next != "")
	}
	if len(page.Sets[0].Draft) != 0 || strings.Contains(read.Body.String(), "must-not-appear-in-metadata") {
		t.Fatal("set list loaded draft contents")
	}
	firstLast := page.Sets[len(page.Sets)-1].ID
	next := do(t, h, "GET", "/admin/api/transforms?state=active&cursor="+url.QueryEscape(page.Next), "", true)
	if next.Code != 200 {
		t.Fatalf("next=%d %s", next.Code, next.Body.String())
	}
	if err := json.Unmarshal(next.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 204 || len(page.Sets) != 50 || page.Sets[0].ID >= firstLast {
		t.Fatal("cursor page lost full filtered count or stable order")
	}
	for _, query := range []string{"limit=201", "state=unknown", "unknown=1", "limit=1&limit=2", "state=disabled&cursor=" + url.QueryEscape(page.Next)} {
		if bad := do(t, h, http.MethodGet, "/admin/api/transforms?"+query, "", true); bad.Code != 400 {
			t.Fatalf("invalid list query accepted: %s %d", query, bad.Code)
		}
	}
}
