package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCreateMigrationBackupIncludesWALAndVerifiedManifest(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay.db")
	db, err := sql.Open("sqlite", dbPath+connPragmas)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; CREATE TABLE evidence (id INTEGER PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO evidence(id, value) VALUES (42, 'visible-from-wal')`); err != nil {
		t.Fatal(err)
	}

	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cipher, err := NewCipher("manifest-key-test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := createMigrationBackup(context.Background(), conn, dbPath, MigrationBackupSpec{
		SourceSchema:      0,
		SourceVariant:     string(legacySchemaM6Current),
		SourceFingerprint: legacyM6CurrentFreshFingerprint,
		TargetSchema:      1,
		LegacyCipherID:    cipher.KeyID(),
		SourceValidator:   "legacy-schema0-v1",
		PairedBuildID:     "test-build",
		ReaderContract:    "pre-p0-reader-v1",
		CreatedAt:         time.Date(2026, 8, 13, 12, 34, 56, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("create backup: %v", err)
	}

	if !strings.Contains(filepath.ToSlash(result.Directory), "/backups/schema-0-to-1-20260813T123456Z-") {
		t.Fatalf("unexpected backup directory %q", result.Directory)
	}
	backupDB, err := sql.Open("sqlite", result.DatabasePath+connPragmas)
	if err != nil {
		t.Fatal(err)
	}
	defer backupDB.Close()
	var got string
	if err := backupDB.QueryRow(`SELECT value FROM evidence WHERE id=42`).Scan(&got); err != nil {
		t.Fatalf("backup omitted WAL-visible row: %v", err)
	}
	if got != "visible-from-wal" {
		t.Fatalf("backup value = %q", got)
	}

	databaseBytes, err := os.ReadFile(result.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	wantSHA := sha256.Sum256(databaseBytes)
	manifestBytes, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted BackupManifest
	if err := json.Unmarshal(manifestBytes, &persisted); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if persisted != result.Manifest {
		t.Fatalf("persisted manifest = %+v, returned = %+v", persisted, result.Manifest)
	}
	if persisted.FormatVersion != 1 || persisted.SourceSchema != 0 || persisted.SourceVariant != string(legacySchemaM6Current) || persisted.TargetSchema != 1 {
		t.Fatalf("manifest source/target fields = %+v", persisted)
	}
	if persisted.DatabaseFile != filepath.Base(result.DatabasePath) || persisted.DatabaseSize != int64(len(databaseBytes)) || persisted.DatabaseSHA256 != hex.EncodeToString(wantSHA[:]) {
		t.Fatalf("manifest database evidence = %+v", persisted)
	}
	if persisted.LegacyCipherID != "211a8cd1e88bfe28" || persisted.PairedBuildID != "test-build" || persisted.ReaderContract != "pre-p0-reader-v1" {
		t.Fatalf("manifest pairing fields = %+v", persisted)
	}
	for _, path := range []string{result.DatabasePath, result.ManifestPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
			t.Fatalf("%s permissions = %o, want 600", path, got)
		}
	}
	if info, err := os.Stat(result.Directory); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o700 {
		t.Fatalf("backup directory permissions = %o, want 700", got)
	}
}

func TestNormalizeLegacyToSchemaOneCreatesBackupBeforeDDL(t *testing.T) {
	for _, variant := range []legacySchemaVariant{
		legacySchemaM2,
		legacySchemaM6PreColumn,
		legacySchemaM6PreIndex,
		legacySchemaM6Current,
	} {
		t.Run(string(variant), func(t *testing.T) {
			db, path, cipher := openLegacyBackupFixture(t, variant)
			before, err := inspectSchemaState(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}

			result, err := normalizeLegacyToSchemaOne(context.Background(), db, path, cipher, MigrationBackupIdentity{
				PairedBuildID:  "test-build",
				ReaderContract: "pre-p0-reader-v1",
				CreatedAt:      time.Date(2026, 8, 13, 13, 0, 0, 0, time.UTC),
			})
			if err != nil {
				t.Fatalf("normalize %s: %v", variant, err)
			}
			if result.Manifest.SourceVariant != string(variant) || result.Manifest.SourceFingerprint != before.Fingerprint {
				t.Fatalf("backup did not identify exact source: %+v", result.Manifest)
			}

			after, err := inspectSchemaState(context.Background(), db)
			if err != nil {
				t.Fatalf("inspect normalized schema: %v", err)
			}
			if after.Version != 1 {
				t.Fatalf("normalized state = %+v, want version 1", after)
			}
			var keyCount int
			if err := db.QueryRow(`SELECT COUNT(*) FROM upstream WHERE name='legacy-upstream'`).Scan(&keyCount); err != nil {
				t.Fatal(err)
			}
			if keyCount != 1 {
				t.Fatalf("normalization lost legacy data, row count=%d", keyCount)
			}

			backupDB, err := sql.Open("sqlite", result.DatabasePath+connPragmas)
			if err != nil {
				t.Fatal(err)
			}
			defer backupDB.Close()
			backupState, err := inspectSchemaState(context.Background(), backupDB)
			if err != nil {
				t.Fatalf("inspect source backup: %v", err)
			}
			if backupState.Variant != variant || backupState.Fingerprint != before.Fingerprint {
				t.Fatalf("backup state = %+v, source = %+v", backupState, before)
			}
		})
	}
}

func TestNormalizeLegacyToSchemaOneFailsBeforeDDLWhenBackupCannotBePublished(t *testing.T) {
	db, path, cipher := openLegacyBackupFixture(t, legacySchemaM6Current)
	before := schemaCatalogSnapshot(t, db)
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "backups"), []byte("block directory creation"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := normalizeLegacyToSchemaOne(context.Background(), db, path, cipher, MigrationBackupIdentity{
		PairedBuildID: "test-build", ReaderContract: "pre-p0-reader-v1",
	})
	if err == nil {
		t.Fatal("backup publication failure must abort migration")
	}
	if after := schemaCatalogSnapshot(t, db); after != before {
		t.Fatalf("schema changed before backup was published\nbefore: %s\nafter: %s", before, after)
	}
}

func TestNormalizeLegacyToSchemaOneRejectsWrongKeyBeforeDDL(t *testing.T) {
	db, path, _ := openLegacyBackupFixture(t, legacySchemaM6Current)
	wrongCipher, err := NewCipher("a-different-encryption-key")
	if err != nil {
		t.Fatal(err)
	}
	before := schemaCatalogSnapshot(t, db)

	_, err = normalizeLegacyToSchemaOne(context.Background(), db, path, wrongCipher, MigrationBackupIdentity{
		PairedBuildID: "test-build", ReaderContract: "pre-p0-reader-v1",
	})
	if err == nil || !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
		t.Fatalf("wrong key error = %v", err)
	}
	if after := schemaCatalogSnapshot(t, db); after != before {
		t.Fatalf("wrong key changed schema\nbefore: %s\nafter: %s", before, after)
	}
}

func openLegacyBackupFixture(t *testing.T, variant legacySchemaVariant) (*sql.DB, string, *Cipher) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path+connPragmas)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	loadLegacyVariantFixture(t, db, variant)
	cipher, err := NewCipher("legacy-encryption-key")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt("sk-legacy-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO upstream
		(name, base_url, api_key_enc, auth_style, full_url_mode, proxy_url, enabled,
		 l1_path, probe_headers, created_at, updated_at)
		VALUES ('legacy-upstream', 'https://legacy.example', ?, 'auto', 0, '', 1,
		 '/v1/models', '', 1, 1)`, encrypted); err != nil {
		t.Fatal(err)
	}
	return db, path, cipher
}
