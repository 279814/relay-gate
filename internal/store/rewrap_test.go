package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		Revision: 1, AggregationWindowSec: 300, RateLimitWindowSec: 300,
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

	if err := st.RewrapDirectSecrets(newMaster, "rid-test"); err != nil {
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

// TestRewrapDirectSecrets_SampleEnvelopeNewMasterAlone pins restart after
// rotation: an enveloped sample sealed under the old master must decrypt with
// only the new master (no retired key), and a leftover plaintext row must stay
// readable and uncorrupted by the rewrap.
func TestRewrapDirectSecrets_SampleEnvelopeNewMasterAlone(t *testing.T) {
	oldMaster := "old-master-sample-rewrap-aaaa"
	newMaster := "new-master-sample-rewrap-bbbb"
	dbPath := filepath.Join(t.TempDir(), "sample-rewrap.db")

	oldC, err := NewCipher(oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	oldID := oldC.KeyID()
	st, err := Open(dbPath, oldC)
	if err != nil {
		t.Fatal(err)
	}

	envBody := []byte(`{"role":"user","content":"enveloped-before-rotate"}`)
	env := &model.Sample{
		ReqID: "req-env", TSRecv: time.Now().UnixMilli(), Endpoint: "/v1/messages",
		InMethod: "POST", InPath: "/v1/messages", InBody: envBody,
		Outcome: model.OutcomeOK,
	}
	if err := st.InsertSample(env); err != nil {
		t.Fatal(err)
	}

	plainBody := []byte(`{"model":"legacy-plaintext","keep":"me"}`)
	empty := []byte{}
	plainID := insertRawSampleGroup(t, st, "legacy-plain", time.Now().UnixMilli(), plainBody, empty, empty)

	var rawEnvBefore, rawPlainBefore []byte
	if err := st.db.QueryRow(`SELECT in_body FROM sample_request WHERE id=?`, env.ID).Scan(&rawEnvBefore); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(rawEnvBefore, []byte("v2:")) || strings.Contains(string(rawEnvBefore), oldID) {
		t.Fatalf("pre-rewrap envelope want key-id %s, got %q", oldID, rawEnvBefore)
	}
	if _, err := st.MigrateSampleEnvelopes(); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT in_body FROM sample_request WHERE id=?`, plainID).Scan(&rawPlainBefore); err != nil {
		t.Fatal(err)
	}

	if err := st.RewrapDirectSecrets(newMaster, "rid-test"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart with only the new master — no retired key in Cipher.previous.
	onlyNew, err := NewCipher(newMaster)
	if err != nil {
		t.Fatal(err)
	}
	newID := onlyNew.KeyID()
	st2, err := Open(dbPath, onlyNew)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st2.Close() })

	var rawEnvAfter, rawPlainAfter []byte
	if err := st2.db.QueryRow(`SELECT in_body FROM sample_request WHERE id=?`, env.ID).Scan(&rawEnvAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawEnvBefore, rawEnvAfter) {
		t.Fatalf("post-rewrap envelope want new key-id %s, got %q", newID, rawEnvAfter)
	}
	if strings.Contains(string(rawEnvAfter), "v1:"+oldID+":") {
		t.Fatal("sample envelope still sealed under old master after rewrap")
	}
	if err := st2.db.QueryRow(`SELECT in_body FROM sample_request WHERE id=?`, plainID).Scan(&rawPlainAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawPlainAfter, rawPlainBefore) {
		t.Fatal("rewrap mutated legacy plaintext sample row")
	}
	if !IsSampleEnvelope(rawPlainAfter) {
		t.Fatal("migrated legacy sample lost its Data Key envelope")
	}

	gotEnv, err := st2.GetSample(env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotEnv.InBody, envBody) {
		t.Fatalf("enveloped sample under new master alone: got %q want %q", gotEnv.InBody, envBody)
	}
	gotPlain, err := st2.GetSample(plainID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPlain.InBody, plainBody) {
		t.Fatalf("plaintext dual-read after rewrap: got %q want %q", gotPlain.InBody, plainBody)
	}
}

// Rotation must never update any sample body, including multipart spill BLOBs.
func TestMasterRotationPreservesMultipartCiphertext(t *testing.T) {
	previous := sampleBlobChunk
	sampleBlobChunk = 4096
	defer func() { sampleBlobChunk = previous }()
	oldCipher, _ := NewCipher("multipart-master-old-at-least-16")
	database := filepath.Join(t.TempDir(), "multipart.db")
	st, err := Open(database, oldCipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	want := bytes.Repeat([]byte("multipart body"), 2000)
	spill := filepath.Join(t.TempDir(), "body.tmp")
	if err := os.WriteFile(spill, want, 0600); err != nil {
		t.Fatal(err)
	}
	sample := mkSample(42)
	sample.InBody, sample.OutBody, sample.RespBody = nil, nil, nil
	sample.RespBodyFile = spill
	if err := st.InsertSample(sample); err != nil {
		t.Fatal(err)
	}
	var before []byte
	if err := st.db.QueryRow(`SELECT resp_body FROM sample_attempt WHERE request_id=?`, sample.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(before, []byte("v2m:")) {
		t.Fatal("spill did not use multipart Data Key envelope")
	}
	for _, statement := range []string{
		`CREATE TEMP TRIGGER prevent_sample_request_rewrite BEFORE UPDATE OF in_body ON sample_request BEGIN SELECT RAISE(ABORT,'sample body must not be reencrypted'); END`,
		`CREATE TEMP TRIGGER prevent_sample_attempt_rewrite BEFORE UPDATE OF out_body,resp_body ON sample_attempt BEGIN SELECT RAISE(ABORT,'sample body must not be reencrypted'); END`,
	} {
		if _, err := st.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RewrapDirectSecrets("multipart-master-new-at-least-16", "multipart-rid"); err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err := st.db.QueryRow(`SELECT resp_body FROM sample_attempt WHERE request_id=?`, sample.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Master rotation changed multipart ciphertext")
	}
	st.Close()
	newCipher, _ := NewCipher("multipart-master-new-at-least-16")
	reopened, err := Open(database, newCipher)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetSample(sample.ID)
	if err != nil || !bytes.Equal(got.RespBody, want) {
		t.Fatalf("restart with only new Master failed: %v", err)
	}
}
