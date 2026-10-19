package main

import (
	"context"
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

	beforeRecovery, _ := kr.Status()
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
	if err := recordRotationRecoveryAudit(st2, beforeRecovery, ks); err != nil {
		t.Fatal(err)
	}
	page, err := st2.ListAuditEventsPage(context.Background(), model.AuditEventFilter{Action: "master_recovery"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Outcome != "succeeded" {
		t.Fatal("completed local rotation recovery was not audited", err)
	}
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

	beforeRecovery, _ := kr.Status()
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
	if err := recordRotationRecoveryAudit(st2, beforeRecovery, ks); err != nil {
		t.Fatal(err)
	}
	page, err := st2.ListAuditEventsPage(context.Background(), model.AuditEventFilter{Action: "master_rotation_rollback"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Outcome != "succeeded" {
		t.Fatal("completed local rollback was not audited", err)
	}
	got, err := st2.GetUpstream(u.ID)
	if err != nil || got.APIKey != apiKey {
		t.Fatalf("upstream must still decrypt under old active: err=%v", err)
	}
}

func TestRecoverMasterRotation_CorruptCommittedDataCannotActivateOrClean(t *testing.T) {
	for _, phase := range []keyring.RotationPhase{keyring.PhasePrepared, keyring.PhaseDBCommitted, keyring.PhaseKeyActivated} {
		t.Run(string(phase), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "relay-gate.db")
			const oldMaster = "old-master-corruption-fixture"
			const newMaster = "new-master-corruption-fixture"
			keys := keyring.Open(dir)
			if err := keys.EnsureInitialized("initial", oldMaster); err != nil {
				t.Fatal(err)
			}
			cipher, err := store.NewCipher(oldMaster)
			if err != nil {
				t.Fatal(err)
			}
			st, err := store.Open(path, cipher)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			u := &model.Upstream{Name: "corruption", BaseURL: "https://fixture.example", APIKey: "sk-corruption-fixture-key", Enabled: true}
			if err := st.CreateUpstream(u); err != nil {
				t.Fatal(err)
			}
			rid, err := keys.BeginRotation(newMaster)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.RewrapDirectSecrets(newMaster, rid); err != nil {
				t.Fatal(err)
			}
			if phase != keyring.PhasePrepared {
				if err := keys.MarkDBCommitted(rid); err != nil {
					t.Fatal(err)
				}
			}
			if phase == keyring.PhaseKeyActivated {
				if _, err := keys.ActivatePending(rid); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := st.DB().Exec(`UPDATE upstream SET api_key_enc='corrupt-ciphertext' WHERE id=?`, u.ID); err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			hold, _, err := recoverMasterRotation(dir, path)
			if err == nil || !hold {
				t.Fatalf("corrupt database admitted: hold=%v err=%v", hold, err)
			}
			status, err := keys.Status()
			if err != nil || status.Phase != phase || status.RotationID != rid {
				t.Fatalf("corrupt recovery advanced its journal: %+v err=%v", status, err)
			}
		})
	}
}

func TestResealPersistedRelayUnderPending_EncryptsLegacyPlaintext(t *testing.T) {
	dir := t.TempDir()
	const oldMaster = "old-master-legacy-relay-fixture"
	const newMaster = "new-master-legacy-relay-fixture"
	const relay = "rk-legacy-plaintext-relay-fixture"
	keys := keyring.Open(dir)
	if err := keys.EnsureInitialized("initial", oldMaster); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.BeginRotation(newMaster); err != nil {
		t.Fatal(err)
	}
	if err := credential.WritePersisted(dir, credential.Persisted{FormatVersion: 1, RelayKey: relay, AdminPasswordHash: "fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := resealPersistedRelayUnderPending(keys, dir); err != nil {
		t.Fatal(err)
	}
	persisted, err := credential.LoadPersistedFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !credential.IsRelayKeyEnvelope(persisted.RelayKey) {
		t.Fatal("recovery retained a plaintext relay key instead of resealing it")
	}
	cipher, err := store.NewCipher(newMaster)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := credential.OpenPersistedRelayKey(persisted.RelayKey, cipher)
	if err != nil || plain != relay {
		t.Fatalf("recovered relay does not open under pending: %v", err)
	}
}
