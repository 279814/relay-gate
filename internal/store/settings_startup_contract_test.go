package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestSettingsStartupInitializesPositiveRevision(t *testing.T) {
	st := testStore(t)
	settings, revision, err := st.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	if revision != 1 || settings.RealFirstSemanticSec != 1200 {
		t.Fatalf("startup default settings revision=%d value=%+v", revision, settings)
	}
}

func TestBackupValidationDoesNotRewriteHistoricalSettingsJSON(t *testing.T) {
	st := testStore(t)
	const legacy = `{"real_first_token_sec":900,"count_tokens_sec":47}`
	if _, err := st.DB().Exec(`UPDATE setting SET value=? WHERE key='settings'`, legacy); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(backup.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), st.DatabasePath(), backup.ManifestPath, st.cipher); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(backup.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only backup validation normalized historical JSON")
	}
	db, err := openReadOnlySQLite(backup.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw string
	if err := db.QueryRow(`SELECT value FROM setting WHERE key='settings'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != legacy {
		t.Fatal("historical reader input was silently changed")
	}
	decoded, err := DecodeLegacySettings([]byte(raw))
	if err != nil || decoded.RealFirstSemanticSec != 900 || decoded.CountTokensTotalSec != 47 {
		t.Fatalf("explicit historical reader lost compatibility: %+v %v", decoded, err)
	}
}

func TestLegacySettingsAreNormalizedOnlyAtControlledStartup(t *testing.T) {
	st := testStore(t)
	const raw = `{"real_first_token_sec":900,"real_first_byte_sec":901,"l2_first_token_sec":240,"l2_first_event_sec":241,"count_tokens_sec":47,"probe_enabled":false}`
	if _, err := st.DB().Exec(`INSERT INTO setting(key,value,updated_at,revision) VALUES('settings',?,1,7) ON CONFLICT(key) DO UPDATE SET value=excluded.value,revision=excluded.revision`, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSettings(); !errors.Is(err, model.ErrValidation) {
		t.Errorf("normal runtime read accepted legacy syntax: %v", err)
	}
	path, cipher := st.DatabasePath(), st.cipher
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	settings, revision, err := reopened.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	if revision != 8 || settings.RealResponseHeaderSec != 900 || settings.RealFirstByteSec != 901 || settings.RealFirstSemanticSec != 900 || settings.L2ResponseHeaderSec != 240 || settings.L2FirstEventSec != 241 || settings.CountTokensConnectSec != 47 || settings.CountTokensTotalSec != 47 {
		t.Fatalf("controlled import lost stage values or revision: %d %+v", revision, settings)
	}
	var stored string
	if err := reopened.DB().QueryRow(`SELECT value FROM setting WHERE key='settings'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"real_first_token_sec", "l2_first_token_sec", "count_tokens_sec", "probe_enabled"} {
		if strings.Contains(stored, `"`+key+`"`) {
			t.Errorf("startup retained legacy storage key %s", key)
		}
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	_, sameRevision, err := again.GetSettingsWithRevision()
	if err != nil || sameRevision != revision {
		t.Fatalf("canonical cold reopen changed revision: %d err=%v", sameRevision, err)
	}
}
