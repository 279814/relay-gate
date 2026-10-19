package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

var retentionIndexNames = []string{"idx_probe_execution_calibration_run", "idx_calibration_candidate_execution",
	"idx_recipe_test_execution", "idx_profile_test_execution", "idx_probe_execution_trigger_created"}

func dropRetentionIndexes(t *testing.T, st *Store) {
	t.Helper()
	for _, name := range retentionIndexNames {
		if _, err := st.db.Exec("DROP INDEX " + name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRetentionIndexesOldAndNewBackupFingerprintsRemainReadOnlyAndRestorable(t *testing.T) {
	st, _, _ := schemaEightDataKeyBackupFixture(t)
	dropRetentionIndexes(t, st)
	state, err := inspectSchemaState(context.Background(), st.db)
	if err != nil || state.Fingerprint != schemaV8FreshFingerprint {
		t.Fatalf("old schema8=%+v %v", state, err)
	}
	old, err := st.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(old.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), st.path, old.ManifestPath, st.cipher); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(old.DatabasePath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("readonly checker changed old backup")
	}
	oldDB := openDatabaseAtPath(t, old.DatabasePath)
	oldState, err := inspectSchemaState(context.Background(), oldDB)
	oldDB.Close()
	if err != nil || oldState.Fingerprint != old.Manifest.SourceFingerprint || oldState.Fingerprint != schemaV8FreshFingerprint {
		t.Fatalf("old backup was upgraded: %+v %v", oldState, err)
	}
	path := st.path
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	cipher, _ := NewCipher("backup-data-key-master-long-enough")
	upgraded, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	indexed, err := inspectSchemaState(context.Background(), upgraded.db)
	if err != nil || indexed.Fingerprint == oldState.Fingerprint {
		t.Fatalf("startup didn't ensure full physical helpers: %+v %v", indexed, err)
	}
	newBackup, err := upgraded.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if newBackup.Manifest.SourceFingerprint != indexed.Fingerprint {
		t.Fatal("manifest omitted full physical fingerprint")
	}
	if _, err := CheckBackup(context.Background(), path, newBackup.ManifestPath, cipher); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreDatabase(context.Background(), path, old.ManifestPath, cipher, true, old.Manifest.ReaderContract); err != nil {
		t.Fatal(err)
	}
	// Restore validates/install the original catalog; only normal Open ensures
	// indexes. Validation must never silently rewrite the restored generation.
	raw := openDatabaseAtPath(t, path)
	restored, err := inspectSchemaState(context.Background(), raw)
	raw.Close()
	if err != nil || restored.Fingerprint != old.Manifest.SourceFingerprint {
		t.Fatalf("restore changed physical catalog: %+v %v", restored, err)
	}
	fresh, _ := NewCipher("backup-data-key-master-long-enough")
	reopened, err := Open(path, fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	final, err := inspectSchemaState(context.Background(), reopened.db)
	if err != nil || final.Fingerprint != indexed.Fingerprint {
		t.Fatalf("restored startup mismatch: %+v %v", final, err)
	}
	after, err = os.ReadFile(old.DatabasePath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("restoration changed the backup artifact")
	}
}

func TestRetentionIndexWhitelistRejectsPartialAndSameNameWrongDefinition(t *testing.T) {
	for _, kind := range []string{"partial", "wrong_definition", "unknown_index"} {
		t.Run(kind, func(t *testing.T) {
			st := testStore(t)
			switch kind {
			case "partial":
				if _, err := st.db.Exec(`DROP INDEX idx_profile_test_execution`); err != nil {
					t.Fatal(err)
				}
			case "wrong_definition":
				if _, err := st.db.Exec(`DROP INDEX idx_recipe_test_execution; CREATE INDEX idx_recipe_test_execution ON probe_recipe(created_at)`); err != nil {
					t.Fatal(err)
				}
			case "unknown_index":
				if _, err := st.db.Exec(`CREATE INDEX unexpected_retention ON probe_execution(created_at)`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := inspectSchemaState(context.Background(), st.db); !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("accepted %s: %v", kind, err)
			}
		})
	}
}

func TestRetentionLookupPlanUsesCalibrationAndReferenceIndexes(t *testing.T) {
	st := testStore(t)
	for _, tc := range []struct{ sql, index string }{
		{`SELECT id FROM probe_execution WHERE calibration_run_id='r' OR id IN(SELECT execution_id FROM calibration_candidate WHERE run_id='r')`, "idx_probe_execution_calibration_run"},
		{`SELECT 1 FROM calibration_candidate WHERE execution_id='e'`, "idx_calibration_candidate_execution"},
		{`SELECT 1 FROM probe_recipe WHERE last_test_execution_id='e'`, "idx_recipe_test_execution"},
		{`SELECT 1 FROM client_probe_profile WHERE tested_execution_id='e'`, "idx_profile_test_execution"},
	} {
		rows, err := st.db.Query("EXPLAIN QUERY PLAN " + tc.sql)
		if err != nil {
			t.Fatal(err)
		}
		var plans []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			plans = append(plans, detail)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(plans, "\n"), tc.index) {
			t.Fatalf("missing %s: %v", tc.index, plans)
		}
	}
}

func TestRetentionIndexEnsureCanceledTransactionDoesNotCreatePartialSet(t *testing.T) {
	st := testStore(t)
	dropRetentionIndexes(t, st)
	before, err := inspectSchemaState(context.Background(), st.db)
	if err != nil || before.Version != developmentSchemaVersion {
		t.Fatalf("schema9 without helper indexes: %+v %v", before, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ensureProbeRetentionIndexes(ctx, st.db); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ensure=%v", err)
	}
	state, err := inspectSchemaState(context.Background(), st.db)
	if err != nil || state != before {
		t.Fatalf("canceled DDL left partial indexes: %+v %v", state, err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ensureProbeRetentionIndexes(ctx, st.db); err != nil {
		t.Fatal(err)
	}
	first, err := inspectSchemaState(context.Background(), st.db)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureProbeRetentionIndexes(ctx, st.db); err != nil {
		t.Fatal(err)
	}
	second, err := inspectSchemaState(context.Background(), st.db)
	if err != nil || first != second {
		t.Fatalf("ensure not idempotent: %+v %+v %v", first, second, err)
	}
}
