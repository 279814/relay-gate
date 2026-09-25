package store

import (
	"bytes"
	"context"
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
	res, err := st.db.Exec(`INSERT INTO sample (
		req_id, ts_recv, ts_sent, ts_first_byte, ts_done,
		endpoint, model_in, model_out, model_name_id, route_id, upstream_id,
		in_method, in_path, in_query, in_headers, in_body,
		out_url, out_headers, out_body,
		resp_status, resp_headers, resp_body,
		outcome, error, truncated, pinned
	) VALUES ('legacy-plain', ?,0,0,0, '/v1/messages','m','m',1,1,1,
		'POST','/v1/messages','','{}',?,
		'https://ex','{}',?,
		200,'{}',?,
		'ok','',0,0)`, time.Now().UnixMilli(), plainBody, empty, empty)
	if err != nil {
		t.Fatal(err)
	}
	plainID, _ := res.LastInsertId()

	var rawEnvBefore, rawPlainBefore []byte
	if err := st.db.QueryRow(`SELECT in_body FROM sample WHERE id=?`, env.ID).Scan(&rawEnvBefore); err != nil {
		t.Fatal(err)
	}
	if !IsSampleEnvelope(rawEnvBefore) || !strings.Contains(string(rawEnvBefore), "v1:"+oldID+":") {
		t.Fatalf("pre-rewrap envelope want key-id %s, got %q", oldID, rawEnvBefore)
	}
	if err := st.db.QueryRow(`SELECT in_body FROM sample WHERE id=?`, plainID).Scan(&rawPlainBefore); err != nil {
		t.Fatal(err)
	}

	if err := st.RewrapDirectSecrets(newMaster); err != nil {
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
	if err := st2.db.QueryRow(`SELECT in_body FROM sample WHERE id=?`, env.ID).Scan(&rawEnvAfter); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawEnvAfter), "v1:"+newID+":") {
		t.Fatalf("post-rewrap envelope want new key-id %s, got %q", newID, rawEnvAfter)
	}
	if strings.Contains(string(rawEnvAfter), "v1:"+oldID+":") {
		t.Fatal("sample envelope still sealed under old master after rewrap")
	}
	if err := st2.db.QueryRow(`SELECT in_body FROM sample WHERE id=?`, plainID).Scan(&rawPlainAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawPlainAfter, rawPlainBefore) {
		t.Fatal("rewrap mutated legacy plaintext sample row")
	}
	if IsSampleEnvelope(rawPlainAfter) {
		t.Fatal("rewrap must not envelope leftover plaintext rows")
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
