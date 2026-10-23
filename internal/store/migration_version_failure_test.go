package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func initializeDriverMigrationSource(ctx context.Context, db *sql.DB, cipher *Cipher, version int) error {
	switch version {
	case 2:
		return initializeEmptySchemaTwo(ctx, db)
	case 3:
		return initializeEmptySchemaThree(ctx, db)
	case 4:
		return initializeEmptySchemaFour(ctx, db)
	case 5:
		return initializeEmptySchemaFive(ctx, db)
	case 6:
		return initializeEmptySchemaSix(ctx, db)
	case 7:
		return initializeEmptySchemaSeven(ctx, db)
	case 8:
		return initializeEmptySchemaEight(ctx, db, cipher)
	case 9:
		return initializeEmptySchemaNine(ctx, db, cipher)
	case 10:
		return initializeEmptySchemaTen(ctx, db, cipher)
	case 11:
		return initializeEmptySchemaEleven(ctx, db, cipher)
	case 12:
		return initializeEmptySchemaTwelve(ctx, db, cipher)
	case 13:
		return initializeEmptySchemaThirteen(ctx, db, cipher)
	case 14:
		return initializeEmptySchemaFourteen(ctx, db, cipher)
	case 15:
		return initializeEmptySchemaFifteen(ctx, db, cipher)
	case 16:
		return initializeEmptySchemaSixteen(ctx, db, cipher)
	}
	return fmt.Errorf("unsupported fixture schema %d", version)
}

func runDriverMigration(ctx context.Context, db *sql.DB, path string, cipher *Cipher, version int) (MigrationBackupResult, error) {
	identity := MigrationBackupIdentity{PairedBuildID: "migration-driver-fixture", CreatedAt: time.Unix(123, 0)}
	switch version {
	case 0:
		identity.ReaderContract = "legacy-reader"
		return normalizeLegacyToSchemaOne(ctx, db, path, cipher, identity)
	case 2:
		return migrateSchemaTwoToThree(ctx, db, path, cipher, identity)
	case 3:
		return migrateSchemaThreeToFour(ctx, db, path, cipher, identity)
	case 4:
		return migrateSchemaFourToFive(ctx, db, path, cipher, identity)
	case 5:
		return migrateSchemaFiveToSix(ctx, db, path, cipher, identity)
	case 6:
		return migrateSchemaSixToSeven(ctx, db, path, cipher, identity)
	case 7:
		return migrateSchemaSevenToEight(ctx, db, path, cipher, identity)
	case 8:
		return migrateSchemaEightToNine(ctx, db, path, cipher, identity, identity.PairedBuildID)
	case 9:
		return migrateSchemaNineToTen(ctx, db, path, cipher, identity, identity.PairedBuildID)
	case 10:
		return migrateSchemaTenToEleven(ctx, db, path, cipher, identity, identity.PairedBuildID)
	case 11:
		return migrateSchemaElevenToTwelve(ctx, db, path, cipher, identity, identity.PairedBuildID)
	case 12:
		return migrateSchemaTwelveToThirteen(ctx, db, path, cipher, identity, identity.PairedBuildID)
	case 13:
		return migrateSchemaThirteenToFourteen(ctx, db, path, cipher, identity, identity.PairedBuildID)
	case 14:
		return migrateSchemaFourteenToFifteen(ctx, db, path, cipher, identity, identity.PairedBuildID)
	case 15:
		return migrateSchemaFifteenToSixteen(ctx, db, path, cipher, identity, identity.PairedBuildID)
	case 16:
		return migrateSchemaSixteenToSeventeen(ctx, db, path, cipher, identity, identity.PairedBuildID)
	}
	return MigrationBackupResult{}, fmt.Errorf("unsupported migration schema %d", version)
}

func TestAllMigrationVersionsRecoverAfterSQLiteDriverErrors(t *testing.T) {
	ctx := context.Background()
	const master = "all-migration-driver-synthetic-master"
	masterCipher, err := NewCipher(master)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := masterCipher.Encrypt("retained synthetic credential")
	if err != nil {
		t.Fatal(err)
	}
	type sourceCase struct {
		name    string
		version int
		variant legacySchemaVariant
		fresh   bool
	}
	cases := []sourceCase{
		{"m2", 0, legacySchemaM2, false},
		{"m6_precolumn", 0, legacySchemaM6PreColumn, false},
		{"m6_preindex", 0, legacySchemaM6PreIndex, false},
		{"m6_current", 0, legacySchemaM6Current, false},
		{"m6_preindex_fresh", 0, legacySchemaM6PreIndex, true},
		{"m6_current_fresh", 0, legacySchemaM6Current, true},
	}
	// The richer schema1 fixture has its own exhaustive driver-boundary test.
	for version := 2; version < developmentSchemaVersion; version++ {
		cases = append(cases, sourceCase{name: fmt.Sprintf("schema%d", version), version: version})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := func(t *testing.T, failAt int) (string, *sql.DB, *Cipher, *migrationDriverFault, inspectedSchemaState) {
				t.Helper()
				cipher, err := NewCipher(master)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "migration.db")
				fault := &migrationDriverFault{failAt: failAt}
				db := sql.OpenDB(&migrationFaultConnector{dsn: path + connPragmas, fault: fault})
				t.Cleanup(func() { _ = db.Close() })
				if tc.version == 0 {
					if tc.fresh {
						loadLegacySchema(t, db)
						if tc.variant == legacySchemaM6Current {
							if _, err := db.Exec(`CREATE INDEX idx_sample_req ON sample (req_id)`); err != nil {
								t.Fatal(err)
							}
						}
					} else {
						loadLegacyVariantFixture(t, db, tc.variant)
					}
				} else if err := initializeDriverMigrationSource(ctx, db, cipher, tc.version); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`INSERT INTO setting(key,value,updated_at) VALUES('driver-fault-sentinel','retained synthetic value',1)`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`INSERT INTO upstream(id,name,base_url,api_key_enc,auth_style,full_url_mode,created_at,updated_at)
					VALUES(7,'synthetic-source','https://fixture.invalid/v1/messages',?,'bearer',?,1,1)`, encrypted, tc.version == 2); err != nil {
					t.Fatal(err)
				}
				before, err := inspectSchemaState(ctx, db)
				if err != nil || before.Version != tc.version {
					t.Fatalf("invalid fixture: %+v %v", before, err)
				}
				fault.armed = true
				return path, db, cipher, fault, before
			}
			path, db, cipher, baseline, _ := fixture(t, 0)
			if _, err := runDriverMigration(ctx, db, path, cipher, tc.version); err != nil {
				t.Fatal(err)
			}
			baseline.armed = false
			target, err := inspectSchemaState(ctx, db)
			if err != nil || target.Version != tc.version+1 {
				t.Fatalf("invalid target: %+v %v", target, err)
			}
			events := append([]migrationDriverEvent(nil), baseline.events...)
			_ = db.Close()
			if len(events) < 5 || !events[len(events)-1].committed {
				t.Fatal("fixture did not exercise the complete production transaction")
			}
			for index, event := range events {
				t.Run(fmt.Sprintf("after-%d-%s", index+1, event.kind), func(t *testing.T) {
					path, db, cipher, fault, before := fixture(t, index+1)
					backup, err := runDriverMigration(ctx, db, path, cipher, tc.version)
					if err == nil || !fault.fired || len(fault.events) != index+1 || fault.events[index] != event {
						t.Fatalf("driver boundary not reached: fired=%v events=%d err=%v", fault.fired, len(fault.events), err)
					}
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					reopened := openDatabaseAtPath(t, path)
					state, err := inspectSchemaState(ctx, reopened)
					want := before
					if event.committed {
						want = target
					}
					if err != nil || state != want {
						t.Fatalf("partial migration survived: got=%+v want=%+v err=%v", state, want, err)
					}
					assertSourceData := func() {
						t.Helper()
						var value, credential string
						if err := reopened.QueryRow(`SELECT value FROM setting WHERE key='driver-fault-sentinel'`).Scan(&value); err != nil || value != "retained synthetic value" {
							t.Fatalf("migration lost source setting: %v", err)
						}
						if err := reopened.QueryRow(`SELECT api_key_enc FROM upstream WHERE id=7`).Scan(&credential); err != nil || credential != encrypted {
							t.Fatalf("migration changed source ciphertext: %v", err)
						}
					}
					assertSourceData()
					var integrity string
					if err := reopened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
						t.Fatalf("integrity=%q err=%v", integrity, err)
					}
					var backupHash string
					if backup.ManifestPath != "" {
						manifest, err := CheckBackup(ctx, path, backup.ManifestPath, cipher)
						if err != nil || manifest.SourceSchema != before.Version || manifest.SourceFingerprint != before.Fingerprint {
							t.Fatalf("invalid source backup: %+v %v", manifest, err)
						}
						_, backupHash, err = fileEvidence(backup.DatabasePath)
						if err != nil {
							t.Fatal(err)
						}
					}
					if !event.committed {
						if _, err := runDriverMigration(ctx, reopened, path, cipher, tc.version); err != nil {
							t.Fatalf("production retry failed: %v", err)
						}
					}
					state, err = inspectSchemaState(ctx, reopened)
					if err != nil || state != target {
						t.Fatalf("retry target=%+v want=%+v err=%v", state, target, err)
					}
					assertSourceData()
					if backupHash != "" {
						_, retainedHash, err := fileEvidence(backup.DatabasePath)
						if err != nil || retainedHash != backupHash {
							t.Fatal("retry overwrote the prior source backup")
						}
					}
					if event.committed {
						_ = reopened.Close()
						freshCipher, err := NewCipher(master)
						if err != nil {
							t.Fatal(err)
						}
						current, err := Open(path, freshCipher)
						if err != nil {
							t.Fatalf("normal startup after uncertain COMMIT failed: %v", err)
						}
						defer current.Close()
						state, err := inspectSchemaState(ctx, current.db)
						if err != nil || state.Version != developmentSchemaVersion {
							t.Fatalf("normal startup schema=%+v err=%v", state, err)
						}
						var value, credential string
						if err := current.db.QueryRow(`SELECT value,api_key_enc FROM setting CROSS JOIN upstream WHERE key='driver-fault-sentinel' AND upstream.id=7`).Scan(&value, &credential); err != nil || value != "retained synthetic value" || credential != encrypted {
							t.Fatalf("normal startup changed source data: %v", err)
						}
					}
				})
			}
			t.Logf("verified %d driver boundaries for %s→schema%d", len(events), tc.name, tc.version+1)
		})
	}
}
