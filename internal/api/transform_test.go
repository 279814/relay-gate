package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
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

// DeleteRoute must detach published transform bindings. After delete + SQLite
// rowid reuse, the reincarnated id must stay passthrough unless it publishes
// anew. A live sibling route must keep its binding.
func TestDeleteRoute_DetachesTransformBindingForReusedID(t *testing.T) {
	s, _ := newTestServer(t)
	reg := transform.NewRegistry(20)
	h := s.WithTransformRegistry(reg).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h, `{"name":"xform-reuse-u","base_url":"https://x.example.com","api_key":"sk-xxxxxxxxxxxx"}`)
	upSibling := mkUpstreamViaAPI(t, h, `{"name":"xform-reuse-u2","base_url":"https://y.example.com","api_key":"sk-yyyyyyyyyyyy"}`)
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"xform-reuse-m","protocol":"anthropic"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("model-name: %d %s", rec.Code, rec.Body.String())
	}
	mnID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("route: %d %s", rec.Code, rec.Body.String())
	}
	routeID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upSibling)+`}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("sibling route: %d %s", rec.Code, rec.Body.String())
	}
	siblingID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	const endpointID int64 = 1
	rec = do(t, h, "POST", "/admin/api/transforms", `{"name":"reuse-set"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("transform set: %d %s", rec.Code, rec.Body.String())
	}
	setID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	rec = do(t, h, "PUT", "/admin/api/transforms/"+itoa(setID)+"/draft",
		`{"rules":[{"kind":"replace_bytes","from":"OLD","to":"NEW"}]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("draft: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, "POST", "/admin/api/transforms/"+itoa(setID)+"/publish",
		`{"route_id":`+itoa(routeID)+`,"endpoint_id":`+itoa(endpointID)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, "POST", "/admin/api/transforms/"+itoa(setID)+"/publish",
		`{"route_id":`+itoa(siblingID)+`,"endpoint_id":`+itoa(endpointID)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("sibling publish: %d %s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, "DELETE", "/admin/api/routes/"+itoa(routeID), "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete route: %d %s", rec.Code, rec.Body.String())
	}
	c, vid, err := reg.PublishedCompiled(routeID, endpointID)
	if err != nil || c != nil || vid != 0 {
		t.Fatalf("deleted route binding must be gone: c=%v id=%d err=%v", c != nil, vid, err)
	}
	cSibling, _, err := reg.PublishedCompiled(siblingID, endpointID)
	if err != nil || cSibling == nil {
		t.Fatalf("live sibling binding must remain: c=%v err=%v", cSibling != nil, err)
	}

	// Empty the route table so AUTOINCREMENT can reuse the deleted id after
	// sqlite_sequence reset (a surviving higher id would force max+1).
	rec = do(t, h, "DELETE", "/admin/api/routes/"+itoa(siblingID), "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete sibling: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := s.st.DB().Exec(`DELETE FROM sqlite_sequence WHERE name='route'`); err != nil {
		t.Fatalf("reset route sequence: %v", err)
	}
	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("recreate route: %d %s", rec.Code, rec.Body.String())
	}
	reusedID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	if reusedID != routeID {
		t.Fatalf("forced reuse failed: new id=%d old=%d", reusedID, routeID)
	}
	c, vid, err = reg.PublishedCompiled(reusedID, endpointID)
	if err != nil || c != nil || vid != 0 {
		t.Fatalf("reused id must stay passthrough: c=%v id=%d err=%v", c != nil, vid, err)
	}
}

// Endpoint delete must detach transform bindings inside the SQL transaction
// (and around it for in-memory state). A failed delete keeps bindings; after a
// successful delete commits, bindings attached for a reused id must survive.
func TestDeleteEndpoint_DetachesTransformBindingForReusedID(t *testing.T) {
	s, _ := newTestServer(t)
	reg := transform.NewRegistry(20).WithPersist(s.st)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).
		WithTransformRegistry(reg).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h,
		`{"name":"xform-ep-u","base_url":"https://ep-x.example.com","api_key":"sk-xxxxxxxxxxxx"}`)

	rec := do(t, h, "GET", "/admin/api/upstream-endpoints?upstream_id="+itoa(upID), "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("list endpoints: %d %s", rec.Code, rec.Body.String())
	}
	page := decodeBody[model.Page[model.UpstreamEndpoint]](t, rec)
	var target, sibling model.UpstreamEndpoint
	for _, ep := range page.Items {
		switch ep.Kind {
		case model.EndpointModels:
			target = ep
		case model.EndpointMessages:
			sibling = ep
		}
	}
	if target.ID == 0 || sibling.ID == 0 {
		t.Fatalf("missing endpoints: target=%d sibling=%d", target.ID, sibling.ID)
	}

	const routeID int64 = 1
	rec = do(t, h, "POST", "/admin/api/transforms", `{"name":"ep-reuse-set"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("transform set: %d %s", rec.Code, rec.Body.String())
	}
	setID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	rec = do(t, h, "PUT", "/admin/api/transforms/"+itoa(setID)+"/draft",
		`{"rules":[{"kind":"replace_bytes","from":"OLD","to":"NEW"}]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("draft: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, "POST", "/admin/api/transforms/"+itoa(setID)+"/publish",
		`{"route_id":`+itoa(routeID)+`,"endpoint_id":`+itoa(target.ID)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish target: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, "POST", "/admin/api/transforms/"+itoa(setID)+"/publish",
		`{"route_id":`+itoa(routeID)+`,"endpoint_id":`+itoa(sibling.ID)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish sibling: %d %s", rec.Code, rec.Body.String())
	}

	// Failed delete (upstream still enabled) must keep bindings.
	rec = do(t, h, "DELETE",
		"/admin/api/upstream-endpoints/"+itoa(target.ID)+"?expected_revision="+itoa(target.Revision),
		"", true)
	if rec.Code == http.StatusNoContent {
		t.Fatal("enabled upstream must reject endpoint delete")
	}
	c, _, err := reg.PublishedCompiled(routeID, target.ID)
	if err != nil || c == nil {
		t.Fatalf("failed delete must keep target binding: c=%v err=%v", c != nil, err)
	}

	rec = do(t, h, "PUT", "/admin/api/upstreams/"+itoa(upID), `{"enabled":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable upstream: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, "DELETE",
		"/admin/api/upstream-endpoints/"+itoa(target.ID)+"?expected_revision="+itoa(target.Revision),
		"", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete endpoint: %d %s", rec.Code, rec.Body.String())
	}
	c, vid, err := reg.PublishedCompiled(routeID, target.ID)
	if err != nil || c != nil || vid != 0 {
		t.Fatalf("deleted endpoint binding must be gone: c=%v id=%d err=%v", c != nil, vid, err)
	}
	cSibling, _, err := reg.PublishedCompiled(routeID, sibling.ID)
	if err != nil || cSibling == nil {
		t.Fatalf("live sibling binding must remain: c=%v err=%v", cSibling != nil, err)
	}

	// Empty endpoint table + reset AUTOINCREMENT so the next create reuses id.
	for _, ep := range page.Items {
		if ep.ID == target.ID {
			continue
		}
		cur, err := s.st.GetEndpoint(ep.ID)
		if err != nil {
			t.Fatal(err)
		}
		rec = do(t, h, "DELETE",
			"/admin/api/upstream-endpoints/"+itoa(cur.ID)+"?expected_revision="+itoa(cur.Revision),
			"", true)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("delete leftover endpoint %d: %d %s", cur.ID, rec.Code, rec.Body.String())
		}
	}
	if _, err := s.st.DB().Exec(`DELETE FROM sqlite_sequence WHERE name='upstream_endpoint'`); err != nil {
		t.Fatalf("reset endpoint sequence: %v", err)
	}

	body := `{"upstream_id":` + itoa(upID) + `,"endpoint":"models","url_mode":"canonical","auth_profile":{"mode":"x_api_key","header_name":"x-api-key","secret_ref":"upstream_api_key"}}`
	rec = do(t, h, "POST", "/admin/api/upstream-endpoints", body, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("recreate endpoint: %d %s", rec.Code, rec.Body.String())
	}
	reused := decodeBody[model.UpstreamEndpoint](t, rec)
	if reused.ID != target.ID {
		t.Fatalf("forced reuse failed: new id=%d old=%d", reused.ID, target.ID)
	}

	rec = do(t, h, "POST", "/admin/api/transforms/"+itoa(setID)+"/publish",
		`{"route_id":`+itoa(routeID)+`,"endpoint_id":`+itoa(reused.ID)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish reused: %d %s", rec.Code, rec.Body.String())
	}
	c, _, err = reg.PublishedCompiled(routeID, reused.ID)
	if err != nil || c == nil {
		t.Fatalf("bindings attached after delete commits must remain: c=%v err=%v", c != nil, err)
	}
}

func itoa64(v int64) string {
	return jsonNumber(v)
}

func jsonNumber(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
