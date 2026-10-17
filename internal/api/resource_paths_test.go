package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestDocumentedProbeResourcePathsReachActualRecords(t *testing.T) {
	s, handler, source, _, calls, recipeID, version, route := recipeHTTPFixture(t)
	profile := &model.ClientProbeProfile{UpstreamID: route.UpstreamID, Endpoint: model.EndpointChatCompletions,
		ClientFamily: "generic", ShapeHash: "canonical-resource-profile", SeenCount: 1}
	if err := s.st.CreateClientProfileCandidate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	source.Invalidate()
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	request := func(method, path, body string, auth bool) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+"/admin/api"+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if auth {
			req.Header.Set("Authorization", "Bearer "+testAdminPW)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	versionPath := fmt.Sprintf("/probe-recipe-versions/%d", version.ID)
	profilePath := fmt.Sprintf("/client-probe-profiles/%d", profile.ID)
	for _, path := range []string{versionPath, profilePath, "/client-probe-profiles?limit=1"} {
		if status, _ := request("GET", path, "", false); status != 401 {
			t.Errorf("resource auth status=%d path=%s", status, path)
		}
		if status, _ := request("GET", path, "", true); status != 200 {
			t.Errorf("documented resource is unreachable: status=%d path=%s", status, path)
		}
	}
	for _, path := range []string{versionPath, profilePath} {
		if status, _ := request("POST", path+"/preview", fmt.Sprintf(`{"route_id":%d}`, route.ID), true); status != 200 {
			t.Errorf("preview unreachable: status=%d path=%s", status, path)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("resource reads or previews sent an upstream request")
	}
	status, raw := request("POST", versionPath+"/test", fmt.Sprintf(`{"expected_revision":2,"route_id":%d}`, route.ID), true)
	if status != 200 {
		t.Fatalf("canonical version test status=%d", status)
	}
	var execution model.ProbeExecution
	if err := json.Unmarshal(raw, &execution); err != nil {
		t.Fatal(err)
	}
	if !execution.Success || calls.Load() != 1 {
		t.Fatal("canonical version test must execute exactly once")
	}
	publish := fmt.Sprintf("/probe-recipes/%d/versions/%d/publish", recipeID, version.ID)
	if status, _ := request("POST", publish, fmt.Sprintf(`{"expected_revision":2,"test_execution_id":%q}`, execution.ID), true); status != 200 {
		t.Fatalf("nested publication contract changed: %d", status)
	}
	if calls.Load() != 1 {
		t.Fatal("publication sent another request")
	}
	for _, path := range []string{"/client-profiles", fmt.Sprintf("/probe-recipes/%d/versions/%d", recipeID, version.ID)} {
		if status, _ := request("GET", path, "", true); status != 404 {
			t.Errorf("retired alternate resource path remains: %s status=%d", path, status)
		}
	}
}
