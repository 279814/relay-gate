package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestSampleBrowserPOSTViewReauthDoesNotInvalidateSession(t *testing.T) {
	s, h := newTestServer(t)
	smp := &model.Sample{Endpoint: "/v1/messages", InMethod: "POST", InHeaders: http.Header{}, InBody: []byte("private-sample-original-body"), Outcome: model.OutcomeOK}
	if err := s.st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	session := loginSession(t, h)
	remote := httptest.NewServer(h)
	defer remote.Close()
	request := func(method, path, body string, cookie *http.Cookie) (int, []byte, http.Header) {
		t.Helper()
		req, err := http.NewRequest(method, remote.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", remote.URL)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		response, err := remote.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw, response.Header
	}
	viewPath := "/admin/api/samples/" + itoa(smp.ID) + "/view"
	for _, action := range []struct{ method, path, body string }{{"POST", viewPath, `{"password":"wrong-password"}`}, {"POST", "/admin/api/samples/" + itoa(smp.ID) + "/pin", `{"pinned":true,"password":"wrong-password"}`}, {"DELETE", "/admin/api/samples", `{"password":"wrong-password"}`}} {
		status, body, _ := request(action.method, action.path, action.body, session)
		if status != http.StatusForbidden || !strings.Contains(string(body), `"code":"reauth_failed"`) || strings.Contains(string(body), "in_body") || strings.Contains(string(body), "private-sample") {
			t.Fatalf("failed reauth returned status=%d body=%s", status, body)
		}
		if status, _, _ := request("GET", "/admin/api/samples", "", session); status != http.StatusOK {
			t.Fatalf("wrong reauth invalidated session: %d", status)
		}
	}
	if current, err := s.st.GetSample(smp.ID); err != nil || current.Pinned {
		t.Fatalf("failed reauth changed sample: err=%v", err)
	}
	status, body, headers := request("POST", viewPath, `{"password":"`+testAdminPW+`"}`, session)
	if status != http.StatusOK || !strings.Contains(headers.Get("Cache-Control"), "no-store") {
		t.Fatalf("POST view=%d %s", status, body)
	}
	var detail model.Sample
	if err := json.Unmarshal(body, &detail); err != nil || string(detail.InBody) != "private-sample-original-body" {
		t.Fatalf("authorized view did not return original bytes: err=%v", err)
	}
	if status, body, _ := request("POST", viewPath, `{"password":"`+testAdminPW+`"}`, nil); status != http.StatusUnauthorized || strings.Contains(string(body), "in_body") {
		t.Fatalf("missing session bypassed auth: %d %s", status, body)
	}
	for _, bad := range []string{`{"password":"` + testAdminPW + `","unknown":true}`, `{"password":"` + testAdminPW + `"}{}`} {
		if status, _, _ := request("POST", viewPath, bad, session); status != http.StatusBadRequest {
			t.Fatalf("non-strict view input=%d", status)
		}
	}
}
