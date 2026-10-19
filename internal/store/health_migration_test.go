package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestSchemaEightHealthMigrationKeepsLegacyUnverifiedAndPairsItsReader(t *testing.T) {
	st, _, _ := schemaEightDataKeyBackupFixture(t)
	route := mkRoute(t, st)
	// Equal timestamps do not establish which incarnation produced the row.
	if _, err := st.db.Exec(`UPDATE route_health SET state='dead',consecutive_fail=99,last_err_at=?,last_error='old unverified',updated_at=? WHERE route_id=?`, route.CreatedAt, route.CreatedAt, route.ID); err != nil {
		t.Fatal(err)
	}
	path := st.path
	st.Close()
	cipher, _ := NewCipher("backup-data-key-master-long-enough")
	current, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	state, err := inspectSchemaState(context.Background(), current.db)
	if err != nil || state.Version != 9 {
		t.Fatalf("schema9=%+v %v", state, err)
	}
	rows, err := current.LoadCurrentRouteHealth(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("legacy rows=%+v %v", rows, err)
	}
	row := rows[0]
	if row.State != model.StateRecovering || !row.LegacyUnverified || row.Identity != nil || row.ConsecutiveFail != 0 || row.LastError != "" || row.CooldownUntil != 0 {
		t.Fatalf("legacy row invented current failure: %+v", row)
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-8-to-9-*", "manifest.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("8→9 backup missing: %v %v", files, err)
	}
	manifest, err := CheckBackup(context.Background(), path, files[0], cipher)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SourceSchema != 8 || manifest.TargetSchema != 9 || manifest.ReaderContract != "schema-8-data-key-v2-reader" || manifest.PairedBuildID == "" {
		t.Fatalf("old reader was reinterpreted: %+v", manifest)
	}
	backupDB := filepath.Join(filepath.Dir(files[0]), manifest.DatabaseFile)
	before, err := os.ReadFile(backupDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), path, files[0], cipher); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(backupDB)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("schema8 reader check modified its artifact")
	}
	old := openDatabaseAtPath(t, backupDB)
	defer old.Close()
	oldState, err := inspectSchemaState(context.Background(), old)
	if err != nil || oldState.Version != 8 {
		t.Fatalf("backup no longer schema8: %+v %v", oldState, err)
	}
}

func TestSchemaNineBackupFailureStopsBeforeAnyHealthDDL(t *testing.T) {
	st, _, _ := schemaEightDataKeyBackupFixture(t)
	path := st.path
	st.Close()
	backups := filepath.Join(filepath.Dir(path), "backups")
	if err := os.Rename(backups, backups+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backups, []byte("backup path blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	cipher, _ := NewCipher("backup-data-key-master-long-enough")
	if opened, err := Open(path, cipher); err == nil {
		opened.Close()
		t.Fatal("migration ignored backup failure")
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil || state.Version != 8 {
		t.Fatalf("failed backup left half-migration: %+v %v", state, err)
	}
	if column, err := hasColumn(db, "route_health", "identity_json"); err != nil || column {
		t.Fatalf("health DDL ran before its backup: column=%t err=%v", column, err)
	}
}

func TestSchemaNineInspectionRejectsPartialOrChangedHealthColumns(t *testing.T) {
	for _, kind := range []string{"partial", "changed", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			st, _, _ := schemaEightDataKeyBackupFixture(t)
			if kind == "partial" {
				if _, err := st.db.Exec(`ALTER TABLE route_health ADD COLUMN cooldown_until INTEGER NOT NULL DEFAULT 0; UPDATE schema_version SET version=9`); err != nil {
					t.Fatal(err)
				}
			} else {
				script, err := migrationFS.ReadFile("migrations/0009_route_health_identity.sql")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := st.db.Exec(string(script)); err != nil {
					t.Fatal(err)
				}
				if _, err := st.db.Exec(`UPDATE schema_version SET version=9`); err != nil {
					t.Fatal(err)
				}
				if kind == "changed" {
					if _, err := st.db.Exec(`ALTER TABLE route_health RENAME COLUMN identity_json TO wrong_identity`); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := st.db.Exec(`CREATE INDEX unreviewed_health ON route_health(state)`); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := schemaCatalogSnapshot(t, st.db)
			if _, err := inspectSchemaState(context.Background(), st.db); !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("accepted %s schema9: %v", kind, err)
			}
			if after := schemaCatalogSnapshot(t, st.db); after != before {
				t.Fatal("inspection changed a rejected schema")
			}
		})
	}
}

func TestMalformedOrFutureHealthIdentityCannotBecomeOptimisticUnknown(t *testing.T) {
	for _, raw := range []string{`{`, `null`, `{"Version":2}`, `{"Version":1}`, `{"Version":1,"unexpected":"private-marker"}`} {
		t.Run(raw, func(t *testing.T) {
			st := testStore(t)
			route := mkRoute(t, st)
			if _, err := st.db.Exec(`UPDATE route_health SET state='dead',identity_json=? WHERE route_id=?`, raw, route.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := st.LoadCurrentRouteHealth(context.Background()); err == nil {
				t.Fatal("corrupt/future proof silently became ordinary unknown")
			}
		})
	}
}
