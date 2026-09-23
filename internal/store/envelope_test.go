package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestCipherEnvelopeRoundTrip(t *testing.T) {
	c, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := c.EncryptEnvelope("sk-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if enc[:3] != "v1:" {
		t.Fatalf("want v1: prefix, got %q", enc)
	}
	plain, err := c.DecryptEnvelope(enc)
	if err != nil || plain != "sk-secret-value" {
		t.Fatalf("plain=%q err=%v", plain, err)
	}
	// Legacy bare encrypt still decrypts via DecryptEnvelope.
	legacy, err := c.Encrypt("legacy-plain")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.DecryptEnvelope(legacy)
	if err != nil || got != "legacy-plain" {
		t.Fatalf("legacy got=%q err=%v", got, err)
	}
}

func TestCipherEnvelopeRejectsWrongKeyID(t *testing.T) {
	c1, _ := NewCipher("passphrase-one-aaaaaaa")
	c2, _ := NewCipher("passphrase-two-bbbbbbb")
	enc, err := c1.EncryptEnvelope("x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.DecryptEnvelope(enc); err == nil {
		t.Fatal("expected key-id mismatch")
	}
}

// TestActivateMaster_NewSampleUsesNewKeyOldEnvelopeDecrypts pins §12.7 + §5.4:
// after live Cipher follows key_activated, new sample ciphertext is under the
// new key-id while envelopes written with the previous master still decrypt
// (Master Key rotation does not re-encrypt all large samples).
func TestActivateMaster_NewSampleUsesNewKeyOldEnvelopeDecrypts(t *testing.T) {
	oldMaster := "old-master-key-aaaaaa"
	newMaster := "new-master-key-bbbbbb"
	c, err := NewCipher(oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	oldID := c.KeyID()
	st, err := Open(filepath.Join(t.TempDir(), "rotate.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	oldBody := []byte(`{"role":"user","content":"before-rotate"}`)
	old := &model.Sample{
		ReqID: "req-old", TSRecv: time.Now().UnixMilli(), Endpoint: "/v1/messages",
		InMethod: "POST", InPath: "/v1/messages", InBody: oldBody,
		Outcome: model.OutcomeOK,
	}
	if err := st.InsertSample(old); err != nil {
		t.Fatal(err)
	}
	var rawOld []byte
	if err := st.db.QueryRow(`SELECT in_body FROM sample WHERE id=?`, old.ID).Scan(&rawOld); err != nil {
		t.Fatal(err)
	}
	if !IsSampleEnvelope(rawOld) || !strings.Contains(string(rawOld), "v1:"+oldID+":") {
		t.Fatalf("pre-rotate envelope want key-id %s, got %q", oldID, rawOld)
	}

	if err := st.ActivateMaster(newMaster); err != nil {
		t.Fatal(err)
	}
	newID := c.KeyID()
	if newID == oldID {
		t.Fatal("ActivateMaster left KeyID unchanged")
	}

	newBody := []byte(`{"role":"user","content":"after-rotate"}`)
	neu := &model.Sample{
		ReqID: "req-new", TSRecv: time.Now().UnixMilli(), Endpoint: "/v1/messages",
		InMethod: "POST", InPath: "/v1/messages", InBody: newBody,
		Outcome: model.OutcomeOK,
	}
	if err := st.InsertSample(neu); err != nil {
		t.Fatal(err)
	}
	var rawNew []byte
	if err := st.db.QueryRow(`SELECT in_body FROM sample WHERE id=?`, neu.ID).Scan(&rawNew); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawNew), "v1:"+newID+":") {
		t.Fatalf("post-rotate ciphertext want new key-id %s, got %q", newID, rawNew)
	}
	if strings.Contains(string(rawNew), "v1:"+oldID+":") {
		t.Fatal("post-rotate sample still encrypted under old key (stale live Cipher)")
	}

	gotOld, err := st.GetSample(old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotOld.InBody) != string(oldBody) {
		t.Fatalf("old envelope decrypt: got %q want %q", gotOld.InBody, oldBody)
	}
	gotNew, err := st.GetSample(neu.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotNew.InBody) != string(newBody) {
		t.Fatalf("new envelope decrypt: got %q want %q", gotNew.InBody, newBody)
	}
}
