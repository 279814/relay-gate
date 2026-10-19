package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/config"
	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/store"
)

func TestMasterRotation_EnvironmentMasterOverrideRejectsBeforeAnyWrite(t *testing.T) {
	s, h, session, keys := newRotationFixture(t)
	t.Setenv("ENCRYPTION_KEY", "old-master-for-rotation-fixture")
	source, ok := any(s).(interface{ WithMasterKeyEnvironmentOverride(bool) *Server })
	if !ok {
		t.Fatal("API cannot enforce the startup master-key source")
	}
	source.WithMasterKeyEnvironmentOverride(strings.TrimSpace(os.Getenv("ENCRYPTION_KEY")) != "")
	before, err := os.ReadFile(keys.Path())
	if err != nil {
		t.Fatal(err)
	}
	var writesBefore int64
	if err := s.st.DB().QueryRow(`SELECT total_changes()`).Scan(&writesBefore); err != nil {
		t.Fatal(err)
	}
	beforeConfig, err := s.st.LoadConfigBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	beforeCredentials := s.creds.Status()
	var lastAuditID int64
	if err := s.st.DB().QueryRow(`SELECT COALESCE(MAX(id),0) FROM audit_event`).Scan(&lastAuditID); err != nil {
		t.Fatal(err)
	}
	status := doSession(t, h, http.MethodGet, "/admin/api/credentials", "", session)
	var state struct {
		Allowed bool   `json:"rotation_allowed"`
		Reason  string `json:"blocked_reason"`
	}
	if err := json.Unmarshal(status.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Allowed || !strings.Contains(state.Reason, "credentials migrate") {
		t.Fatal("credential state does not explain the required migration")
	}
	response := doSession(t, h, http.MethodPost, "/admin/api/credentials/rotate-master",
		`{"password":"`+testAdminPW+`","new_master":"new-master-must-never-apply"}`, session)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "credentials migrate") {
		t.Fatalf("environment master rotation was not safely rejected: status=%d body=%s", response.Code, response.Body.String())
	}
	after, err := os.ReadFile(keys.Path())
	if err != nil {
		t.Fatal(err)
	}
	var writesAfter int64
	if err := s.st.DB().QueryRow(`SELECT total_changes()`).Scan(&writesAfter); err != nil {
		t.Fatal(err)
	}
	afterConfig, err := s.st.LoadConfigBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := s.st.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE id>? AND action='master_rotate' AND outcome='failed' AND reason_code='conflict'`, lastAuditID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	// Only the matching audit INSERT + terminal UPDATE may change SQLite.
	// The original zero-mutation condition remains for every domain row/key.
	if string(before) != string(after) || writesAfter-writesBefore != 2 || auditCount != 1 ||
		!reflect.DeepEqual(beforeConfig, afterConfig) || !reflect.DeepEqual(beforeCredentials, s.creds.Status()) || s.runState.InMaintenance() {
		t.Fatal("environment rejection changed keyring/database or entered maintenance")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(s.st.DatabasePath()), "backups")); !os.IsNotExist(err) {
		t.Fatal("environment rejection created a backup or journal")
	}
	metadata, err := keys.Status()
	if err != nil || metadata.Phase != keyring.PhaseIdle {
		t.Fatalf("environment rejection advanced journal: %+v err=%v", metadata, err)
	}
}

func TestMasterRotation_MigratedEnvironmentCanRotateAndColdRestart(t *testing.T) {
	initial, _, _, _ := newRotationFixture(t)
	path := initial.st.DatabasePath()
	dir := filepath.Dir(path)
	u := &model.Upstream{Name: "migrated-env", BaseURL: "https://fixture.example", APIKey: "sk-migrated-environment-fixture", Enabled: true}
	if err := initial.st.CreateUpstream(u); err != nil {
		t.Fatal(err)
	}
	if err := initial.st.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_KEY", "old-master-for-rotation-fixture")
	t.Setenv("ADMIN_PASSWORD", testAdminPW)
	t.Setenv("RELAY_KEYS", "rk-rotation-fixture-relay-key")
	t.Setenv("RELAY_DB", path)
	migration := credential.Migration{DataDir: dir, DBPath: path, EncKey: os.Getenv("ENCRYPTION_KEY"),
		AdminPW: os.Getenv("ADMIN_PASSWORD"), RelayKeys: []string{os.Getenv("RELAY_KEYS")}, Out: io.Discard}
	if err := migration.Run(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ENCRYPTION_KEY", "ADMIN_PASSWORD", "RELAY_KEYS"} {
		t.Setenv(name, "")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := store.NewCipher(cfg.EncKey)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	creds := credential.New().WithEnvelope(cipher).WithDataDir(dir)
	if err := creds.SetActiveRelayKeys(cfg.RelayKeys); err != nil {
		t.Fatal(err)
	}
	ctrl, err := runstate.NewController(st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ctrl.Close)
	hash, err := credential.LoadAdminHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, slog.New(slog.NewTextHandler(io.Discard, nil))).WithCredentials(creds, keyring.Open(dir)).WithRunState(ctrl).
		WithAdminHash(hash, dir).WithMasterKeyEnvironmentOverride(strings.TrimSpace(os.Getenv("ENCRYPTION_KEY")) != "")
	installRotationWriteBarriers(t, s)
	h := s.Routes(cfg.AdminPW)
	session := loginSession(t, h)
	response := doSession(t, h, http.MethodPost, "/admin/api/credentials/rotate-master",
		`{"password":"`+testAdminPW+`","new_master":"new-master-after-environment-migration"}`, session)
	if response.Code != http.StatusOK {
		t.Fatalf("migrated keyring could not rotate: %d %s", response.Code, response.Body.String())
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.EncKey != "new-master-after-environment-migration" || len(after.RelayKeys) != 1 || after.RelayKeys[0] != "rk-rotation-fixture-relay-key" {
		t.Fatal("cold configuration did not load the rotated master and persisted relay")
	}
	coldCipher, err := store.NewCipher(after.EncKey)
	if err != nil {
		t.Fatal(err)
	}
	cold, err := store.Open(path, coldCipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cold.Close() })
	fresh, err := cold.GetUpstream(u.ID)
	if err != nil || fresh.APIKey != "sk-migrated-environment-fixture" {
		t.Fatalf("cold restart cannot open migrated upstream: %v", err)
	}
}
