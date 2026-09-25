package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// TestRewrapDirectSecrets_NewMasterAloneDecrypts pins §12.7 step 7: after
// rewrap, upstream / probe / SMTP ciphertext opens under the new master alone
// and no longer under the old master alone.
func TestRewrapDirectSecrets_NewMasterAloneDecrypts(t *testing.T) {
	oldMaster := "old-master-rewrap-test-aaaa"
	newMaster := "new-master-rewrap-test-bbbb"
	c, err := NewCipher(oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(filepath.Join(t.TempDir(), "rewrap.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	const (
		apiKey   = "sk-upstream-before-rewrap"
		probeVal = "probe-secret-before-rewrap"
		smtpPW   = "smtp-password-before-rewrap"
	)
	u := &model.Upstream{
		Name: "rewrap-up", BaseURL: "https://rewrap.example.com",
		APIKey: apiKey, Enabled: true,
	}
	if err := st.CreateUpstream(u); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateProbeSecret("rewrap-probe", []byte(probeVal)); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSMTPConfig(SMTPConfig{
		Host: "mail.example.com", Port: 587, From: "a@example.com",
		Recipients: "ops@example.com", Username: "smtp-user",
	}, smtpPW); err != nil {
		t.Fatal(err)
	}

	var oldAPIEnc, oldProbeEnc, oldSMTPEnc string
	if err := st.db.QueryRow(`SELECT api_key_enc FROM upstream WHERE id=?`, u.ID).Scan(&oldAPIEnc); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT value_enc FROM probe_secret WHERE name=?`, "rewrap-probe").Scan(&oldProbeEnc); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT password_enc FROM smtp_config WHERE singleton=1`).Scan(&oldSMTPEnc); err != nil {
		t.Fatal(err)
	}

	if err := st.RewrapDirectSecrets(newMaster); err != nil {
		t.Fatal(err)
	}
	if err := st.ActivateMaster(newMaster); err != nil {
		t.Fatal(err)
	}

	gotU, err := st.GetUpstream(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotU.APIKey != apiKey {
		t.Fatalf("upstream after rewrap: got %q", gotU.APIKey)
	}
	gotProbe, err := st.ResolveProbeSecret(context.Background(), "rewrap-probe")
	if err != nil {
		t.Fatal(err)
	}
	if string(gotProbe.Plain) != probeVal {
		t.Fatalf("probe after rewrap: got %q", gotProbe.Plain)
	}
	gotSMTP, err := st.SMTPPasswordDecrypt()
	if err != nil {
		t.Fatal(err)
	}
	if gotSMTP != smtpPW {
		t.Fatalf("smtp after rewrap: got %q", gotSMTP)
	}

	var newAPIEnc, newProbeEnc, newSMTPEnc string
	if err := st.db.QueryRow(`SELECT api_key_enc FROM upstream WHERE id=?`, u.ID).Scan(&newAPIEnc); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT value_enc FROM probe_secret WHERE name=?`, "rewrap-probe").Scan(&newProbeEnc); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT password_enc FROM smtp_config WHERE singleton=1`).Scan(&newSMTPEnc); err != nil {
		t.Fatal(err)
	}
	if newAPIEnc == oldAPIEnc || newProbeEnc == oldProbeEnc || newSMTPEnc == oldSMTPEnc {
		t.Fatal("rewrap left at least one ciphertext unchanged")
	}

	onlyOld, err := NewCipher(oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	onlyNew, err := NewCipher(newMaster)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := onlyOld.Decrypt(newAPIEnc); err == nil {
		t.Fatal("upstream ciphertext still decrypts with old master alone")
	}
	if _, err := onlyOld.Decrypt(newProbeEnc); err == nil {
		t.Fatal("probe ciphertext still decrypts with old master alone")
	}
	if _, err := onlyOld.DecryptEnvelope(newSMTPEnc); err == nil {
		t.Fatal("smtp ciphertext still decrypts with old master alone")
	}
	if p, err := onlyNew.Decrypt(newAPIEnc); err != nil || p != apiKey {
		t.Fatalf("new master upstream: plain=%q err=%v", p, err)
	}
	if p, err := onlyNew.Decrypt(newProbeEnc); err != nil || p != probeVal {
		t.Fatalf("new master probe: plain=%q err=%v", p, err)
	}
	if p, err := onlyNew.DecryptEnvelope(newSMTPEnc); err != nil || p != smtpPW {
		t.Fatalf("new master smtp: plain=%q err=%v", p, err)
	}
}
