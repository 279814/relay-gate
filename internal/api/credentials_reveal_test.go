package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/store"
)

// TestRevealRelayKey_ViewAfterReauth covers §12.6: envelope-sealed current key
// is returned after password check (not by rotating); list omits it; wrong
// password is 401; digest auth still accepts the revealed value.
func TestRevealRelayKey_ViewAfterReauth(t *testing.T) {
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	const raw = "rk_reveal_current_key_value_32b"
	creds := credential.New().WithEnvelope(c)
	if err := creds.SetActiveRelayKey(raw); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(st, log).WithCredentials(creds, nil)
	h := s.Routes(testAdminPW)

	bad := do(t, h, "POST", "/admin/api/credentials/reveal-relay",
		`{"password":"not-the-admin"}`, true)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password want 401, got %d body=%s", bad.Code, bad.Body.String())
	}

	list := do(t, h, "GET", "/admin/api/credentials", "", true)
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	listBody := list.Body.String()
	if strings.Contains(listBody, raw) {
		t.Fatal("GET /credentials must not contain raw relay key")
	}
	if strings.Contains(listBody, "v1:") || strings.Contains(listBody, "relayActiveEnc") {
		t.Fatal("GET /credentials must not contain envelope ciphertext")
	}
	var status map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if _, ok := status["relay_key"]; ok {
		t.Fatal("list must not expose relay_key field")
	}

	ok := do(t, h, "POST", "/admin/api/credentials/reveal-relay",
		`{"password":"`+testAdminPW+`"}`, true)
	if ok.Code != http.StatusOK {
		t.Fatalf("reveal want 200, got %d body=%s", ok.Code, ok.Body.String())
	}
	if cc := ok.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control want no-store, got %q", cc)
	}
	var out struct {
		RelayKey string `json:"relay_key"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.RelayKey != raw {
		t.Fatalf("revealed=%q want %q", out.RelayKey, raw)
	}
	if !creds.ValidRelayKey(out.RelayKey) {
		t.Fatal("revealed key must still authorize on digest hot path")
	}
}
