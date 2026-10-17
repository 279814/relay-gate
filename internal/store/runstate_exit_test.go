package store

import (
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestCanonicalRunStateCASAndColdRestartIgnoreLegacyShadow(t *testing.T) {
	st := testStore(t)
	if _, err := st.db.Exec(`INSERT INTO setting(key,value,updated_at,revision) VALUES ('run_state','running',1,1)`); err != nil {
		t.Fatal(err)
	}
	_, revision, err := st.GetRunStateWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	next, err := st.SetRunStateWithRevision(model.RunStatePaused, revision)
	if err != nil || next != revision+1 {
		t.Fatalf("pause revision=%d err=%v", next, err)
	}
	if _, err := st.SetRunStateWithRevision(model.RunStateRunning, revision); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale write=%v", err)
	}
	var legacy string
	if err := st.db.QueryRow(`SELECT value FROM setting WHERE key='run_state'`).Scan(&legacy); err != nil || legacy != "running" {
		t.Fatalf("runtime rewrote migration-only legacy shadow: %q err=%v", legacy, err)
	}
	path, cipher := st.DatabasePath(), st.cipher
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	state, restoredRevision, err := reopened.GetRunStateWithRevision()
	if err != nil || state != model.RunStatePaused || restoredRevision != next {
		t.Fatalf("canonical paused state lost on cold restart: state=%s revision=%d err=%v", state, restoredRevision, err)
	}
}
