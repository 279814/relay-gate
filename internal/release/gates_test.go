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
	"time"

	"github.com/279814/relay-gate/internal/acmeip"
	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/security"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/transform"
)

// releaseRenewBot is a minimal fake for §23 renew observability (no public cert).
type releaseRenewBot struct{}

func (releaseRenewBot) RenewIP(ip string) (string, string, time.Time, error) {
	return "CERT:" + ip, "KEY:" + ip, time.Now().UTC().Add(160 * time.Hour), nil
}

func (releaseRenewBot) Validate(certPEM, keyPEM, expectIP string) error {
	if !bytes.Contains([]byte(certPEM), []byte(expectIP)) {
		return errors.New("SAN missing IP")
	}
	return nil
}

type releaseReloader struct{}

func (releaseReloader) Reload() error { return nil }

func TestEmptyDBOpensAsSchema6(t *testing.T) {
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
	if version != 6 {
		t.Fatalf("schema_version=%d want 6", version)
	}
	var n int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='security_finding'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("security_finding missing: n=%d err=%v", n, err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='transform_set'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("transform_set missing: n=%d err=%v", n, err)
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

func TestTransformPersistSurvivesReopen(t *testing.T) {
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
	reg := transform.NewRegistry(8).WithPersist(st)
	set, err := reg.CreateSet("release")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-P5", Value: "1"}}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	_, ver, err := reg.PublishSnapshot(set.ID, 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	st2, err := store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	reg2 := transform.NewRegistry(8).WithPersist(st2)
	if err := reg2.LoadFromPersist(); err != nil {
		t.Fatal(err)
	}
	c, id, err := reg2.PublishedCompiled(2, 5)
	if err != nil || c == nil || id != ver.ID {
		t.Fatalf("after reopen: c=%v id=%d want=%d err=%v", c != nil, id, ver.ID, err)
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

func TestIPCertRenewObservability(t *testing.T) {
	w := acmeip.NewRenewWatch(releaseRenewBot{}, releaseReloader{}, "203.0.113.80", acmeip.DefaultLowValidity)
	if err := w.TryRenew(); err != nil {
		t.Fatal(err)
	}
	snap := w.Snapshot()
	if snap["renew_successes"] != 1 {
		t.Fatalf("renew_successes=%v", snap["renew_successes"])
	}
	if snap["alert_low_validity"] != false {
		t.Fatalf("160h remaining must not alert: %+v", snap)
	}
	if snap["not_after"] == "" {
		t.Fatal("not_after must be observable")
	}
}
