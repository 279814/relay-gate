package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/store"
)

// 管理端 body 只允许一个 JSON 值。Decoder.Decode 会读完第一个对象就停，
// 若不拒绝尾随值，第一个对象会被写入 store——这是配置注入面。

func TestDecodeJSON_RejectsTrailingSecondValue(t *testing.T) {
	server, handler := newTestServer(t)

	created := do(t, handler, http.MethodPost, "/admin/api/upstreams",
		`{"name":"keep","base_url":"https://keep.example.com","api_key":"sk-keep-key-12","auth_style":"bearer"}`, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("seed create = %d: %s", created.Code, created.Body.String())
	}
	list, err := server.st.ListUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("seed upstreams = %d, want 1", len(list))
	}
	id := list[0].ID
	beforeName := list[0].Name

	// 两个对象：必须 400，且既不新建也不改已有行。
	dupCreate := do(t, handler, http.MethodPost, "/admin/api/upstreams",
		`{"name":"ok","base_url":"https://ok.example.com","api_key":"sk-ok-key-1234","auth_style":"bearer"}{"name":"evil"}`, true)
	if dupCreate.Code != http.StatusBadRequest {
		t.Fatalf("trailing create = %d: %s, want 400", dupCreate.Code, dupCreate.Body.String())
	}

	dupUpdate := do(t, handler, http.MethodPut, "/admin/api/upstreams/"+itoa(id),
		`{"name":"evil"}{"name":"worse"}`, true)
	if dupUpdate.Code != http.StatusBadRequest {
		t.Fatalf("trailing update = %d: %s, want 400", dupUpdate.Code, dupUpdate.Body.String())
	}

	after, err := server.st.ListUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 {
		t.Fatalf("after trailing bodies upstreams = %d, want 1 (no insert)", len(after))
	}
	if after[0].ID != id || after[0].Name != beforeName {
		t.Fatalf("row changed after reject: id=%d name=%q, want id=%d name=%q",
			after[0].ID, after[0].Name, id, beforeName)
	}
}

func TestDecodeJSON_SingleObjectStillSaves(t *testing.T) {
	_, handler := newTestServer(t)

	// 单个对象，以及对象后仅空白，都应正常写入。
	for _, body := range []string{
		`{"name":"one","base_url":"https://one.example.com","api_key":"sk-one-key-123","auth_style":"bearer"}`,
		`{"name":"two","base_url":"https://two.example.com","api_key":"sk-two-key-123","auth_style":"bearer"}` + " \n\t",
	} {
		rec := do(t, handler, http.MethodPost, "/admin/api/upstreams", body, true)
		if rec.Code != http.StatusCreated {
			t.Fatalf("valid create = %d: %s (body=%q)", rec.Code, rec.Body.String(), body)
		}
	}
}

// Decode failures must use a fixed message: decoder errors can embed request
// values (unknown field names, UnmarshalTypeError.Value for numbers, etc.).
func TestDecodeJSON_ErrorOmitsBodySecret(t *testing.T) {
	const fixtureSecret = "sk-FIXTURE-DECODE-SECRET-99"

	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "decode-secret.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s := New(st, log)
	h := s.Routes(testAdminPW)

	// Unknown field name equals the fixture secret so a naive "%v"/err.Error()
	// wrap would echo it into the 400 body (DisallowUnknownFields).
	body := `{"name":"x","base_url":"https://x.example.com","api_key":"sk-ok-key-1234","auth_style":"bearer","` +
		fixtureSecret + `":true}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/upstreams", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminPW)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	resp := rec.Body.String()
	if strings.Contains(resp, fixtureSecret) {
		t.Fatalf("response leaked fixture secret")
	}
	if !strings.Contains(resp, "请求体不是合法 JSON") {
		t.Fatalf("response missing fixed decode message (len=%d)", len(resp))
	}
	if strings.Contains(logBuf.String(), fixtureSecret) {
		t.Fatalf("log leaked fixture secret")
	}
}
