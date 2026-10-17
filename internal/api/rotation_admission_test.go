package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/store"
)

func TestMasterRotation_MaintenanceRejectsEncryptedAdminWrites(t *testing.T) {
	s, h := newTestServer(t)
	ctrl, err := runstate.NewController(s.st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ctrl.Close)
	s.WithRunState(ctrl)
	if err := ctrl.EnterMaintenance("master_key_rotation"); err != nil {
		t.Fatal(err)
	}
	created := do(t, h, http.MethodPost, "/admin/api/upstreams",
		`{"name":"must-not-enter","base_url":"https://fixture.example","api_key":"sk-rotation-write-fence-secret"}`, true)
	if created.Code != http.StatusConflict {
		t.Fatalf("maintenance admitted an encrypted write: status=%d body=%s", created.Code, created.Body.String())
	}
	values, err := s.st.ListUpstreams()
	if err != nil || len(values) != 0 {
		t.Fatalf("rejected write reached storage: count=%d err=%v", len(values), err)
	}
	if read := do(t, h, http.MethodGet, "/admin/api/upstreams", "", true); read.Code != http.StatusOK {
		t.Fatalf("read-only administration became unavailable: status=%d", read.Code)
	}
}

func TestMasterRotation_BackupPairsOldDatabaseAndCredentialRootBeforePreparation(t *testing.T) {
	s, h, session, _ := newRotationFixture(t)
	response := doSession(t, h, http.MethodPost, "/admin/api/credentials/rotate-master",
		`{"password":"`+testAdminPW+`","new_master":"new-master-paired-backup-fixture"}`, session)
	if response.Code != http.StatusOK {
		t.Fatalf("rotation failed: %d %s", response.Code, response.Body.String())
	}
	var result struct {
		BackupManifest string `json:"backup_manifest"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	oldCipher, err := store.NewCipher("old-master-for-rotation-fixture")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CheckBackup(context.Background(), s.st.DatabasePath(), result.BackupManifest, oldCipher)
	if err != nil {
		t.Fatalf("rotation did not retain a verified old-master backup: %v", err)
	}
	archive, err := os.ReadFile(filepath.Join(filepath.Dir(result.BackupManifest), manifest.SecretsFile))
	if err != nil {
		t.Fatal(err)
	}
	var files map[string][]byte
	if err := json.Unmarshal(archive, &files); err != nil {
		t.Fatal(err)
	}
	var oldKeys struct {
		Active string `json:"active"`
		Phase  string `json:"phase"`
	}
	if err := json.Unmarshal(files["keyring.json"], &oldKeys); err != nil {
		t.Fatal(err)
	}
	if oldKeys.Active != "old-master-for-rotation-fixture" || oldKeys.Phase != "" {
		t.Fatal("backup was taken after preparing or activating a different key")
	}
	if err := store.ValidateDatabaseEncryption(context.Background(), filepath.Join(filepath.Dir(result.BackupManifest), manifest.DatabaseFile), oldKeys.Active); err != nil {
		t.Fatalf("database backup does not pair with its own archived keyring: %v", err)
	}
}

func TestMasterRotation_BackupFailureChangesNoKeys(t *testing.T) {
	s, h, session, keys := newRotationFixture(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(s.st.DatabasePath()), "backups"), []byte("blocked directory"), 0600); err != nil {
		t.Fatal(err)
	}
	response := doSession(t, h, http.MethodPost, "/admin/api/credentials/rotate-master",
		`{"password":"`+testAdminPW+`","new_master":"new-master-backup-must-fail"}`, session)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("backup failure did not refuse rotation: %d", response.Code)
	}
	status, err := keys.Status()
	if err != nil || status.Phase != keyring.PhaseIdle || status.HasPending || s.runState.InMaintenance() {
		t.Fatalf("failed backup advanced key state: %+v err=%v", status, err)
	}
	if err := s.st.ValidateEncryptedState(); err != nil {
		t.Fatalf("failed backup changed database encryption: %v", err)
	}
}

func newRotationFixture(t *testing.T) (*Server, http.Handler, *http.Cookie, *keyring.File) {
	t.Helper()
	dir := t.TempDir()
	cipher, err := store.NewCipher("old-master-for-rotation-fixture")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "relay-gate.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	keys := keyring.Open(dir)
	if err := keys.EnsureInitialized(cipher.KeyID(), "old-master-for-rotation-fixture"); err != nil {
		t.Fatal(err)
	}
	creds := credential.New().WithEnvelope(cipher).WithDataDir(dir)
	if err := creds.SetActiveRelayKey("rk-rotation-fixture-relay-key"); err != nil {
		t.Fatal(err)
	}
	sealed, err := cipher.EncryptEnvelope("rk-rotation-fixture-relay-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.WritePersisted(dir, credential.Persisted{
		FormatVersion: 1, AdminPasswordHash: "fixture-hash", RelayKey: sealed, MasterKeyID: cipher.KeyID(),
	}); err != nil {
		t.Fatal(err)
	}
	ctrl, err := runstate.NewController(st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ctrl.Close)
	s := New(st, slog.New(slog.NewTextHandler(io.Discard, nil))).WithCredentials(creds, keys).WithRunState(ctrl)
	installRotationWriteBarriers(t, s)
	h := s.Routes(testAdminPW)
	return s, h, loginSession(t, h), keys
}

func installRotationWriteBarriers(t *testing.T, s *Server) {
	t.Helper()
	settings := model.DefaultSettings()
	recorder := sample.NewRecorder(s.st, settings, nil, s.log)
	logs := sample.NewLogRecorder(s.st, settings, nil, s.log)
	t.Cleanup(recorder.Close)
	t.Cleanup(logs.Close)
	s.WithRotationQuiescer(func(ctx context.Context) (func(), error) {
		if err := recorder.Flush(ctx); err != nil {
			return nil, err
		}
		if err := logs.Flush(ctx); err != nil {
			return nil, err
		}
		// This fixture has no proxy handler; its real writes are the two
		// recorders above and the independently fenced administration routes.
		return func() {}, nil
	})
}

func TestMasterRotation_FailedQuiescenceChangesNoKeys(t *testing.T) {
	s, h, session, keys := newRotationFixture(t)
	s.rotationQuiesce = func(context.Context) (func(), error) {
		return nil, context.DeadlineExceeded
	}
	response := doSession(t, h, http.MethodPost, "/admin/api/credentials/rotate-master",
		`{"password":"`+testAdminPW+`","new_master":"new-master-never-applied"}`, session)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("rotation ignored failed quiescence: status=%d body=%s", response.Code, response.Body.String())
	}
	st, err := keys.Status()
	if err != nil || st.Phase != keyring.PhaseIdle || st.HasPending {
		t.Fatalf("quiescence failure prepared a key: %+v err=%v", st, err)
	}
	if s.runState.InMaintenance() {
		t.Fatal("preparation failure left an otherwise usable database in maintenance")
	}
}

func TestMasterRotation_DrainsAcceptedEncryptedWriteAndRejectsNewWrites(t *testing.T) {
	s, h, session, keys := newRotationFixture(t)
	u := &model.Upstream{Name: "concurrent-write", BaseURL: "https://fixture.example", APIKey: "sk-before-rotation-fixture", Enabled: true}
	if err := s.st.CreateUpstream(u); err != nil {
		t.Fatal(err)
	}
	tx, err := s.st.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	writeResult := make(chan int, 1)
	go func() {
		response := doSession(t, h, http.MethodPut, "/admin/api/upstreams/"+itoa(u.ID),
			`{"api_key":"sk-accepted-before-rotation"}`, session)
		writeResult <- response.Code
	}()
	deadline := time.Now().Add(time.Second)
	for {
		s.mutations.mu.Lock()
		active := s.mutations.active
		s.mutations.mu.Unlock()
		if active == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("encrypted admin write was not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	rotationResult := make(chan int, 1)
	go func() {
		response := doSession(t, h, http.MethodPost, "/admin/api/credentials/rotate-master",
			`{"password":"`+testAdminPW+`","new_master":"new-master-drained-write-fixture"}`, session)
		rotationResult <- response.Code
	}()
	for !s.runState.InMaintenance() {
		if time.Now().After(deadline) {
			t.Fatal("rotation did not close admission")
		}
		time.Sleep(time.Millisecond)
	}
	blocked := doSession(t, h, http.MethodPut, "/admin/api/upstreams/"+itoa(u.ID),
		`{"api_key":"sk-must-never-write-old-master"}`, session)
	if blocked.Code != http.StatusConflict {
		t.Fatalf("new write entered during rotation drain: %d", blocked.Code)
	}
	status, err := keys.Status()
	if err != nil || status.Phase != keyring.PhaseIdle {
		t.Fatalf("rotation prepared before the accepted write finished: %+v err=%v", status, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	for name, result := range map[string]<-chan int{"accepted write": writeResult, "rotation": rotationResult} {
		select {
		case code := <-result:
			if code != http.StatusOK {
				t.Fatalf("%s failed: %d", name, code)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s did not finish", name)
		}
	}
	fresh, err := s.st.GetUpstream(u.ID)
	if err != nil || fresh.APIKey != "sk-accepted-before-rotation" {
		t.Fatalf("accepted write was not sealed under the activated master: err=%v", err)
	}
	if err := s.st.ValidateEncryptedState(); err != nil {
		t.Fatalf("rotation left mixed master ciphertexts: %v", err)
	}
}

type failingRelayCipher struct{ cipher *store.Cipher }

func (f failingRelayCipher) EncryptEnvelope(value string) (string, error) {
	return f.cipher.EncryptEnvelope(value)
}
func (f failingRelayCipher) DecryptEnvelope(string) (string, error) {
	return "", errors.New("injected relay envelope authentication failure")
}

func TestMasterRotation_PostCommitFailureKeepsPendingKeyAndMaintenance(t *testing.T) {
	s, h, session, keys := newRotationFixture(t)
	cipher, err := store.NewCipher("old-master-for-rotation-fixture")
	if err != nil {
		t.Fatal(err)
	}
	s.creds.WithEnvelope(failingRelayCipher{cipher: cipher})
	response := doSession(t, h, http.MethodPost, "/admin/api/credentials/rotate-master",
		`{"password":"`+testAdminPW+`","new_master":"new-master-post-commit-fixture"}`, session)
	if response.Code != http.StatusInternalServerError || !s.runState.InMaintenance() {
		t.Fatalf("post-commit failure did not hold maintenance: status=%d", response.Code)
	}
	status, err := keys.Status()
	if err != nil || status.Phase != keyring.PhasePrepared || !status.HasPending {
		t.Fatalf("post-commit failure lost its pending key: %+v err=%v", status, err)
	}
	rid, err := store.CommittedMasterRotation(s.st.DatabasePath())
	if err != nil || rid != status.RotationID {
		t.Fatalf("fixture must have committed the same rotation: err=%v", err)
	}
	if err := store.ValidateDatabaseEncryption(context.Background(), s.st.DatabasePath(), "new-master-post-commit-fixture"); err != nil {
		t.Fatalf("committed database must remain recoverable with pending: %v", err)
	}
	if err := store.ValidateDatabaseEncryption(context.Background(), s.st.DatabasePath(), "old-master-for-rotation-fixture"); err == nil {
		t.Fatal("committed data still depended on the old master")
	}
}
