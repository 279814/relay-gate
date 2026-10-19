package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func schemaThirteenCanaryFixture(t *testing.T) (*Store, *Cipher) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "canary.db")
	cipher, err := NewCipher("canary-migration-master-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaThirteen(context.Background(), db, cipher); err != nil {
		t.Fatal(err)
	}
	st := &Store{db: db, cipher: cipher, path: path}
	t.Cleanup(func() { st.Close() })
	return st, cipher
}

func TestCanaryMigrationPreservesSchemaThirteenAndPairsBackup(t *testing.T) {
	st, cipher := schemaThirteenCanaryFixture(t)
	encrypted, err := cipher.EncryptEnvelope("synthetic-migration-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE smtp_config SET host='smtp.example.test',password_enc=?,aggregation_window_sec=7,revision=3;
 INSERT INTO probe_cost_event(event_id,day_utc,event_kind,evidence_version,cost_evidence_hash) VALUES('historical','2026-10-19','execution',1,'historical-digest')`, encrypted); err != nil {
		t.Fatal(err)
	}
	before, err := inspectSchemaState(context.Background(), st.db)
	if err != nil {
		t.Fatal(err)
	}
	path := st.path
	st.Close()
	current, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	state, err := inspectSchemaState(context.Background(), current.db)
	if err != nil || state.Version != developmentSchemaVersion {
		t.Fatalf("canary schema=%+v err=%v", state, err)
	}
	var after []byte
	var aggregation, revision int
	if err := current.db.QueryRow(`SELECT password_enc,aggregation_window_sec,revision FROM smtp_config`).Scan(&after, &aggregation, &revision); err != nil || string(after) != string(encrypted) || aggregation != 7 || revision != 3 {
		t.Fatalf("changed historical credential/policy: %v", err)
	}
	var source, hash string
	if err := current.db.QueryRow(`SELECT canary_source,cost_evidence_hash FROM probe_cost_event WHERE event_id='historical'`).Scan(&source, &hash); err != nil || source != "" || hash != "historical-digest" {
		t.Fatalf("invented old Canary source: %q %v", source, err)
	}
	var count int
	if err := current.db.QueryRow(`SELECT COUNT(*) FROM canary_policy`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("migration enabled periodic Canary: %d %v", count, err)
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-13-to-14-*", "manifest.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("schema13 paired backup=%v err=%v", files, err)
	}
	manifest, err := CheckBackup(context.Background(), path, files[0], cipher)
	if err != nil || manifest.SourceFingerprint != before.Fingerprint || manifest.SourceValidator != "schema-13-smtp-policy-v1" || manifest.ReaderContract != "schema-13-smtp-policy-v1-reader" {
		t.Fatalf("schema13 backup=%+v %v", manifest, err)
	}
	backup := openDatabaseAtPath(t, filepath.Join(filepath.Dir(files[0]), manifest.DatabaseFile))
	defer backup.Close()
	if err := backup.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'canary_%'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("Canary DDL preceded backup: %d %v", count, err)
	}
	if err := backup.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('probe_cost_event') WHERE name='canary_source'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("event DDL preceded backup: %d %v", count, err)
	}
}

func TestCanaryMigrationBackupFailureLeavesThirteen(t *testing.T) {
	st, cipher := schemaThirteenCanaryFixture(t)
	path := st.path
	st.Close()
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "backups"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, cipher); err == nil {
		opened.Close()
		t.Fatal("Canary migration ignored failed backup")
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil || state.Version != 13 {
		t.Fatalf("source changed: %+v %v", state, err)
	}
}

func TestCanaryRotationBackupPinsReaderAndRestoresFacts(t *testing.T) {
	st, _ := schemaFourteenSampleFixture(t)
	route := mkRoute(t, st)
	execution := model.ProbeExecution{ID: "canary-paired-fact", Trigger: model.TriggerManual, UpstreamID: route.UpstreamID, RouteID: route.ID,
		Endpoint: model.EndpointMessages, RecipeBindingUse: model.BindingResolved, RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic,
		TemplateID: "builtin:canary-v1", RecipeIdentityRevision: 1, EvidenceHash: "synthetic-execution-hash", ErrorClass: model.ErrorNone, Capability: model.CapabilityUnknown,
		Scope: model.ScopeRouteEndpoint, ObservationOrder: 1, SentAtMS: 1792368000000, DoneAtMS: 1792368001000, Final: true, Success: true}
	if err := st.InsertProbeExecution(context.Background(), &execution); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO canary_execution(execution_id,source,policy_revision,expectation_version,nonce_sha256,expected_tool,verdict,nonce_matched,tool_matched,output_usage_present,evidence_hash)
		VALUES(?,'manual',0,1,?,'relay_canary_noop','passed',1,1,1,?)`, execution.ID, strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO canary_policy(upstream_id,route_id,interval_sec,revision) VALUES(?,?,900,3);
 INSERT INTO canary_cost_daily(day_utc,source,endpoint,route_id,upstream_id,executions,requests,passed,unknown_output_rows) VALUES('2026-10-19','manual','messages',?,?,2,2,1,1)`, route.UpstreamID, route.ID, route.ID, route.UpstreamID); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m := backup.Manifest; m.SourceSchema != 14 || m.TargetSchema != 14 || m.SourceValidator != "schema-14-canary-v1" || m.ReaderContract != "schema-14-canary-v1-reader" {
		t.Fatalf("Canary reader=%+v", m)
	}
	bad := backup.Manifest
	bad.ReaderContract = "schema-13-smtp-policy-v1-reader"
	raw, _ := json.Marshal(bad)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("accepted old Canary reader: %v", err)
	}
	raw, _ = json.Marshal(backup.Manifest)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	path, cipher := st.path, st.cipher
	st.Close()
	result, err := RestoreDatabase(context.Background(), path, backup.ManifestPath, cipher, true, backup.Manifest.ReaderContract)
	if err != nil || result.RestoredSchemaVersion != 14 {
		t.Fatalf("restored Canary=%+v %v", result, err)
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	var enabled, interval, revision, unknown int
	if err := db.QueryRow(`SELECT enabled,interval_sec,revision FROM canary_policy`).Scan(&enabled, &interval, &revision); err != nil || enabled != 0 || interval != 900 || revision != 3 {
		t.Fatalf("lost Canary policy: %d/%d/%d %v", enabled, interval, revision, err)
	}
	if err := db.QueryRow(`SELECT unknown_output_rows FROM canary_cost_daily`).Scan(&unknown); err != nil || unknown != 1 {
		t.Fatalf("lost unknown usage: %d %v", unknown, err)
	}
	var source, nonce string
	if err := db.QueryRow(`SELECT source,nonce_sha256,output_usage_present FROM canary_execution WHERE execution_id=?`, execution.ID).Scan(&source, &nonce, &unknown); err != nil || source != "manual" || nonce != strings.Repeat("a", 64) || unknown != 1 {
		t.Fatalf("lost paired immutable Canary facts: %s %v", source, err)
	}
}

func TestCanarySchemaRejectsPartialChangedUnknown(t *testing.T) {
	for _, mutation := range []string{
		`DROP TABLE canary_execution`,
		`DROP INDEX idx_canary_execution_source`,
		`ALTER TABLE probe_cost_event RENAME COLUMN canary_source TO guessed_source`,
		`CREATE INDEX unknown_canary ON canary_policy(enabled)`,
		`PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'interval_sec BETWEEN 300 AND 86400','interval_sec BETWEEN 1 AND 86400') WHERE name='canary_policy'; PRAGMA writable_schema=OFF`,
	} {
		t.Run(strings.Split(mutation, " ")[0]+mutation[:min(len(mutation), 48)], func(t *testing.T) {
			st := testStore(t)
			if _, err := st.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			before := schemaCatalogSnapshot(t, st.db)
			if _, err := inspectSchemaState(context.Background(), st.db); !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("accepted modified Canary schema: %v", err)
			}
			if schemaCatalogSnapshot(t, st.db) != before {
				t.Fatal("inspection repaired unknown Canary schema")
			}
		})
	}
}

func TestCanarySchemaConstraintsBoundFacts(t *testing.T) {
	st := testStore(t)
	route := mkRoute(t, st)
	for _, values := range []string{"1,299,1", "2,3600,1", "1,3600,0"} {
		if _, err := st.db.Exec(`INSERT INTO canary_policy(upstream_id,route_id,enabled,interval_sec,revision) VALUES(?,?,`+values+`)`, route.UpstreamID, route.ID); err == nil {
			t.Fatalf("accepted invalid policy %s", values)
		}
	}
	if _, err := st.db.Exec(`INSERT INTO canary_execution(execution_id,source,policy_revision,expectation_version,nonce_sha256,expected_tool,verdict,evidence_hash) VALUES('missing','manual',0,1,?,'relay_canary_noop','passed',?)`, strings.Repeat("a", 64), strings.Repeat("b", 64)); err == nil {
		t.Fatal("accepted unpaired Canary execution")
	}
	if _, err := st.db.Exec(`INSERT INTO canary_execution(execution_id,source,policy_revision,expectation_version,nonce_sha256,expected_tool,verdict,evidence_hash) VALUES(NULL,'manual',0,1,?,'relay_canary_noop','incomplete',?)`, strings.Repeat("a", 64), strings.Repeat("b", 64)); err == nil {
		t.Fatal("accepted null execution identity without a paired Probe")
	}
	if _, err := st.db.Exec(`INSERT INTO canary_cost_daily(day_utc,source,endpoint,route_id,upstream_id,requests) VALUES('2026-10-19','manual','messages',?,?,-1)`, route.ID, route.UpstreamID); err == nil {
		t.Fatal("accepted negative Canary cost")
	}
}
