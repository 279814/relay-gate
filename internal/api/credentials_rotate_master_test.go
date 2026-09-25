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
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/store"
)

// TestRotateMaster_RewrapsSecretsForRevealAndDecrypt pins §12.7: after a
// successful master rotation, reveal-relay returns the same current relay key
// and at least one other sealed secret (upstream api_key) still decrypts under
// the new master. The rotation response must not include relay or SMTP secrets.
func TestRotateMaster_RewrapsSecretsForRevealAndDecrypt(t *testing.T) {
	oldMaster := "old-master-api-rotate-aaaa"
	newMaster := "new-master-api-rotate-bbbb"
	c, err := store.NewCipher(oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "api.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	const (
		rawRelay = "rk_survive_master_rotation_32b"
		apiKey   = "sk-upstream-survives-rotation"
		smtpPW   = "smtp-pw-survives-rotation"
	)
	u := &model.Upstream{
		Name: "rot-up", BaseURL: "https://rot.example.com",
		APIKey: apiKey, Enabled: true,
	}
	if err := st.CreateUpstream(u); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSMTPConfig(store.SMTPConfig{
		Host: "mail.example.com", Port: 587, From: "a@example.com",
		Recipients: "ops@example.com", Username: "u",
	}, smtpPW); err != nil {
		t.Fatal(err)
	}

	creds := credential.New().WithEnvelope(c)
	if err := creds.SetActiveRelayKey(rawRelay); err != nil {
		t.Fatal(err)
	}

	kr := keyring.Open(filepath.Join(dir, "secrets"))
	if err := kr.EnsureInitialized("mk_boot", oldMaster); err != nil {
		t.Fatal(err)
	}
	runCtrl, err := runstate.NewController(st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runCtrl.Close)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(st, log).WithCredentials(creds, kr).WithRunState(runCtrl)
	h := s.Routes(testAdminPW)

	body := `{"password":"` + testAdminPW + `","new_master":"` + newMaster + `"}`
	rot := do(t, h, "POST", "/admin/api/credentials/rotate-master", body, true)
	if rot.Code != http.StatusOK {
		t.Fatalf("rotate-master want 200, got %d body=%s", rot.Code, rot.Body.String())
	}
	rotBody := rot.Body.String()
	if strings.Contains(rotBody, rawRelay) || strings.Contains(rotBody, smtpPW) ||
		strings.Contains(rotBody, apiKey) {
		t.Fatalf("rotation response must not include secrets: %s", rotBody)
	}
	var rotOut map[string]any
	if err := json.Unmarshal(rot.Body.Bytes(), &rotOut); err != nil {
		t.Fatal(err)
	}
	if _, ok := rotOut["relay_key"]; ok {
		t.Fatal("rotation response must not include relay_key")
	}
	if _, ok := rotOut["password"]; ok {
		t.Fatal("rotation response must not include password")
	}

	reveal := do(t, h, "POST", "/admin/api/credentials/reveal-relay",
		`{"password":"`+testAdminPW+`"}`, true)
	if reveal.Code != http.StatusOK {
		t.Fatalf("reveal-relay want 200, got %d body=%s", reveal.Code, reveal.Body.String())
	}
	var out struct {
		RelayKey string `json:"relay_key"`
	}
	if err := json.Unmarshal(reveal.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.RelayKey != rawRelay {
		t.Fatalf("reveal after rotation: got %q want %q", out.RelayKey, rawRelay)
	}

	gotU, err := st.GetUpstream(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotU.APIKey != apiKey {
		t.Fatalf("upstream after rotation: got %q", gotU.APIKey)
	}
	gotSMTP, err := st.SMTPPasswordDecrypt()
	if err != nil {
		t.Fatal(err)
	}
	if gotSMTP != smtpPW {
		t.Fatalf("smtp after rotation: got %q", gotSMTP)
	}
}
