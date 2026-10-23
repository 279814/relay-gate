package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"modernc.org/sqlite"
)

// SQLite's real page limit makes the production migration fail with SQLITE_FULL
// without filling a developer/runner disk or adding a production fault hook.
func TestMigrationStorageFullKeepsSourceAndBackupRecoverable(t *testing.T) {
	ctx := context.Background()
	cipher, err := NewCipher("migration-storage-fixture-master")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt("synthetic-migration-storage-credential")
	if err != nil {
		t.Fatal(err)
	}
	identity := MigrationBackupIdentity{PairedBuildID: "storage-full-fixture", ReaderContract: "schema-1-reader", CreatedAt: time.Unix(123, 0)}
	fixture := func(t *testing.T) (string, *sql.DB, inspectedSchemaState, int) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "storage-full.db")
		db := openDatabaseAtPath(t, path)
		if err := initializeEmptySchemaOne(ctx, db); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO upstream(id,name,base_url,api_key_enc,auth_style,created_at,updated_at)
		 VALUES(1,'storage-fixture','https://fixture.invalid',?,'bearer',1,1);
		 INSERT INTO model_name(id,name,protocol,created_at,updated_at) VALUES(1,'fixture','anthropic',1,1);
		 INSERT INTO route(id,model_name_id,upstream_id,created_at,updated_at) VALUES(1,1,1,1,1)`, encrypted); err != nil {
			t.Fatal(err)
		}
		state, err := inspectSchemaState(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		var pages int
		if err := db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
			t.Fatal(err)
		}
		return path, db, state, pages
	}
	path, baseline, _, sourcePages := fixture(t)
	if _, err := migrateSchemaOneToTwo(ctx, baseline, path, cipher, identity); err != nil {
		t.Fatal(err)
	}
	var targetPages int
	if err := baseline.QueryRow(`PRAGMA page_count`).Scan(&targetPages); err != nil || targetPages <= sourcePages+2 {
		t.Fatalf("fixture did not grow enough: source=%d target=%d err=%v", sourcePages, targetPages, err)
	}
	if err := baseline.Close(); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{sourcePages, sourcePages + (targetPages-sourcePages)/2, targetPages - 1} {
		t.Run(fmt.Sprintf("page-limit-%d", limit), func(t *testing.T) {
			path, db, before, pages := fixture(t)
			if pages != sourcePages {
				t.Fatal("fixture page count changed")
			}
			var actualLimit int
			if err := db.QueryRow(fmt.Sprintf(`PRAGMA max_page_count=%d`, limit)).Scan(&actualLimit); err != nil || actualLimit != limit {
				t.Fatalf("page limit not installed: %d %v", actualLimit, err)
			}
			backup, err := migrateSchemaOneToTwo(ctx, db, path, cipher, identity)
			var storageError *sqlite.Error
			if !errors.As(err, &storageError) || storageError.Code()&255 != 13 {
				t.Fatalf("expected real SQLITE_FULL, got %v", err)
			}
			after, err := inspectSchemaState(ctx, db)
			if err != nil || after != before {
				t.Fatalf("failed migration leaked schema/DDL: %+v %v", after, err)
			}
			var integrity, ciphertext string
			if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
				t.Fatalf("source integrity=%q err=%v", integrity, err)
			}
			if err := db.QueryRow(`SELECT api_key_enc FROM upstream WHERE id=1`).Scan(&ciphertext); err != nil || ciphertext != encrypted {
				t.Fatal("failed migration changed source credentials")
			}
			manifest, err := CheckBackup(ctx, path, backup.ManifestPath, cipher)
			if err != nil || manifest.SourceSchema != 1 || manifest.SourceFingerprint != before.Fingerprint {
				t.Fatalf("pre-DDL backup is not recoverable: %v", err)
			}
			_, backupHash, err := fileEvidence(backup.DatabasePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			// A new production Open must migrate the intact source, with no test
			// page limit or manual data repair leaking into the retry.
			st, err := Open(path, cipher)
			if err != nil {
				t.Fatalf("restart after SQLITE_FULL failed: %v", err)
			}
			defer st.Close()
			state, err := inspectSchemaState(ctx, st.db)
			if err != nil || state.Version != developmentSchemaVersion {
				t.Fatalf("retry did not reach current schema: %+v %v", state, err)
			}
			if err := st.db.QueryRow(`SELECT api_key_enc FROM upstream WHERE id=1`).Scan(&ciphertext); err != nil || ciphertext != encrypted {
				t.Fatal("retry changed source credentials")
			}
			_, retainedHash, err := fileEvidence(backup.DatabasePath)
			if err != nil || retainedHash != backupHash {
				t.Fatal("retry overwrote the earlier backup generation")
			}
		})
	}
}
