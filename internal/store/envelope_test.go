package store

import "testing"

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
