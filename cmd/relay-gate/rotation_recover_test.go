package main

import (
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// TestRecoverMasterRotation_PreparedAfterDBCommitRollsForward pins §12.7: a
// rotation that failed after the SQLite rewrap committed (relay reseal or
// MarkDBCommitted error, or a crash) leaves the keyring at prepared. Restart
// must roll forward to the pending key the rows are sealed under, not abort
// and discard it, and the persisted Relay Key must open under the new active.
func TestRecoverMasterRotation_PreparedAfterDBCommitRollsForward(t *testing.T) {
	const (
		oldMaster = "old-master-recover-aaaaaaaa"
		newMaster = "new-master-recover-bbbbbbbb"
		apiKey    = "sk-upstream-survives-recovery"
		rawRelay  = "rk_survives_recovery_32bytes!!"
	)
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "relay-gate.db")

	kr := keyring.Open(dataDir)
	if err := kr.EnsureInitialized("mk_old", oldMaster); err != nil {
		t.Fatal(err)
	}
	oldC, err := store.NewCipher(oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	sealedRelay, err := oldC.EncryptEnvelope(rawRelay)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.WritePersisted(dataDir, credential.Persisted{
		AdminPasswordHash: "hash", RelayKey: sealedRelay, MasterKeyID: "mk_old",
	}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath, oldC)
	if err != nil {
		t.Fatal(err)
	}
	u := &model.Upstream{Name: "recover-up", BaseURL: "https://recover.example.com", APIKey: apiKey, Enabled: true}
	if err := st.CreateUpstream(u); err != nil {
		t.Fatal(err)
	}

	rid, err := kr.BeginRotation(newMaster)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RewrapDirectSecrets(newMaster, rid); err != nil {
		t.Fatal(err)
	}
	// Rotation stops here: keyring still prepared, relay file still under old.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	hold, ks, err := recoverMasterRotation(dataDir, dbPath)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if hold || ks.HasPending {
		t.Fatalf("recovery should finish without hold or pending: hold=%v %+v", hold, ks)
	}
	_, active, err := keyring.Open(dataDir).LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	if active != newMaster {
		t.Fatal("prepared with committed DB must activate the pending key, not discard it")
	}

	newC, err := store.NewCipher(active)
	if err != nil {
		t.Fatal(err)
	}
	st2, err := store.Open(dbPath, newC)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	got, err := st2.GetUpstream(u.ID)
	if err != nil {
		t.Fatalf("upstream must decrypt under the surviving key: %v", err)
	}
	if got.APIKey != apiKey {
		t.Fatal("upstream api key changed across recovery")
	}
	doc, err := credential.LoadPersistedFile(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := credential.OpenPersistedRelayKey(doc.RelayKey, newC)
	if err != nil || plain != rawRelay {
		t.Fatalf("persisted relay key must open under the new active: err=%v", err)
	}
}

// TestRecoverMasterRotation_PreparedWithoutDBCommitAborts keeps the other
// §12.7 branch: rewrap never committed, so pending is dropped and the old
// active still opens the rows.
func TestRecoverMasterRotation_PreparedWithoutDBCommitAborts(t *testing.T) {
	const (
		oldMaster = "old-master-recover-cccccccc"
		newMaster = "new-master-recover-dddddddd"
		apiKey    = "sk-upstream-stays-on-old"
	)
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "relay-gate.db")

	kr := keyring.Open(dataDir)
	if err := kr.EnsureInitialized("mk_old", oldMaster); err != nil {
		t.Fatal(err)
	}
	oldC, err := store.NewCipher(oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath, oldC)
	if err != nil {
		t.Fatal(err)
	}
	u := &model.Upstream{Name: "abort-up", BaseURL: "https://abort.example.com", APIKey: apiKey, Enabled: true}
	if err := st.CreateUpstream(u); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.BeginRotation(newMaster); err != nil {
		t.Fatal(err)
	}

	hold, ks, err := recoverMasterRotation(dataDir, dbPath)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if hold || ks.HasPending || ks.Phase != keyring.PhaseIdle {
		t.Fatalf("uncommitted prepared must abort: hold=%v %+v", hold, ks)
	}
	_, active, err := keyring.Open(dataDir).LoadActive()
	if err != nil || active != oldMaster {
		t.Fatalf("old active must remain: err=%v", err)
	}
	st2, err := store.Open(dbPath, oldC)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	got, err := st2.GetUpstream(u.ID)
	if err != nil || got.APIKey != apiKey {
		t.Fatalf("upstream must still decrypt under old active: err=%v", err)
	}
}
