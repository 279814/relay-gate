// Package release holds P5 cross-cutting release validation gates.
//
// These tests do not replace package-level coverage; they assert the
// v1.0.0 release invariants that span store, keyring, security, and transform.
package release

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/security"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/transform"
)

func TestEmptyDBOpensAsSchema3(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	cipher, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var version int
	if err := st.DB().QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 3 {
		t.Fatalf("schema_version=%d want 3", version)
	}
}

func TestKeyringCrashSafeBootstrap(t *testing.T) {
	dir := t.TempDir()
	f := keyring.Open(dir)
	if err := f.EnsureInitialized("boot", "master-secret-value-32b!!!!"); err != nil {
		t.Fatal(err)
	}
	// Simulate process restart: new handle, same files.
	f2 := keyring.Open(dir)
	id, secret, err := f2.LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	if id != "boot" || secret != "master-secret-value-32b!!!!" {
		t.Fatalf("restart load: %q %q", id, secret)
	}
}

func TestRestoreRejectedWithoutAuthorization(t *testing.T) {
	root := t.TempDir()
	livePath := filepath.Join(root, "relay.db")
	cipher, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(livePath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	// No manifest → must reject without moving files.
	_, err = store.CheckBackup(context.Background(), livePath, filepath.Join(root, "missing.json"), cipher)
	if err == nil {
		t.Fatal("expected CheckBackup failure on missing manifest")
	}
	_, err = store.RestoreDatabase(context.Background(), livePath, filepath.Join(root, "missing.json"), cipher, true, "anything")
	if err == nil {
		t.Fatal("expected RestoreDatabase failure")
	}
	if !errors.Is(err, store.ErrRestoreRejected) && err != nil {
		// Either ErrRestoreRejected or path error is acceptable; must not succeed.
		t.Logf("restore err=%v (ok if non-nil)", err)
	}
}

func TestSecurityScanDoesNotMutate(t *testing.T) {
	in := []byte(`hello <script>alert(1)</script> world`)
	cp := append([]byte(nil), in...)
	findings := security.ScanText(string(in), "release")
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}
	if !bytes.Equal(in, cp) {
		t.Fatal("ScanText mutated input bytes")
	}
}

func TestTransformUnboundPassthrough(t *testing.T) {
	reg := transform.NewRegistry(8)
	c, id, err := reg.PublishedCompiled(42, 7)
	if err != nil || c != nil || id != 0 {
		t.Fatalf("unbound: c=%v id=%d err=%v", c, id, err)
	}
	body := []byte(`{"model":"x"}`)
	h := http.Header{"Authorization": []string{"Bearer k"}}
	if transform.HashBytes(body) != transform.HashBytes(append([]byte(nil), body...)) {
		t.Fatal("body hash drift")
	}
	if transform.HeaderFingerprint(h) != transform.HeaderFingerprint(h.Clone()) {
		t.Fatal("header fingerprint drift")
	}
}

func TestRecoveryGateSingleFlight(t *testing.T) {
	g := health.NewRecoveryGate()
	release1, ok1 := g.TryAcquire(99)
	if !ok1 {
		t.Fatal("first enter should succeed")
	}
	_, ok2 := g.TryAcquire(99)
	if ok2 {
		t.Fatal("second concurrent half-open must fail")
	}
	release1()
	release3, ok3 := g.TryAcquire(99)
	if !ok3 {
		t.Fatal("after release should succeed")
	}
	release3()
}
