package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// TestGetSample_RequiresReauth covers §16.3: unredacted sample bodies are not
// returned on an admin session alone. passwordOK (same as reveal/rotate) must
// pass; wrong/missing password is 401 with no body fields.
func TestGetSample_RequiresReauth(t *testing.T) {
	s, h := newTestServer(t)

	const secret = "private-conversation-must-not-leak"
	smp := &model.Sample{
		ReqID:       "reauth-sample",
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
	path := "/admin/api/samples/" + itoa(smp.ID)

	noPW := do(t, h, "GET", path, "", true)
	if noPW.Code != http.StatusUnauthorized {
		t.Fatalf("session alone want 401, got %d body=%s", noPW.Code, noPW.Body.String())
	}
	if strings.Contains(noPW.Body.String(), secret) || strings.Contains(noPW.Body.String(), "in_body") {
		t.Fatalf("no-password response must not include sample body: %s", noPW.Body.String())
	}

	bad := do(t, h, "GET", path, `{"password":"not-the-admin"}`, true)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password want 401, got %d body=%s", bad.Code, bad.Body.String())
	}
	if strings.Contains(bad.Body.String(), secret) || strings.Contains(bad.Body.String(), "in_body") {
		t.Fatalf("wrong-password response must not include sample body: %s", bad.Body.String())
	}

	ok := do(t, h, "GET", path, `{"password":"`+testAdminPW+`"}`, true)
	if ok.Code != http.StatusOK {
		t.Fatalf("correct password want 200, got %d body=%s", ok.Code, ok.Body.String())
	}
	if cc := ok.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control want no-store, got %q", cc)
	}
	var out struct {
		InBody []byte `json:"in_body"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if string(out.InBody) != secret {
		t.Fatalf("in_body=%q want %q", out.InBody, secret)
	}

	list := do(t, h, "GET", "/admin/api/samples", "", true)
	if list.Code != http.StatusOK {
		t.Fatalf("list session-only want 200, got %d body=%s", list.Code, list.Body.String())
	}
	if strings.Contains(list.Body.String(), secret) {
		t.Fatal("list must not include unredacted sample body")
	}
}
