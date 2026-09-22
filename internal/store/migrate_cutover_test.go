package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestInitializeEmptySchemaThree(t *testing.T) {
	db := openSchemaTestDB(t, "empty-to-v3.db")
	if err := initializeEmptySchemaThree(context.Background(), db); err != nil {
		t.Fatalf("initialize schema 3: %v", err)
	}
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 3 {
		t.Fatalf("state = %+v, want version 3", state)
	}
	if state.Fingerprint != schemaV3FreshFingerprint {
		t.Fatalf("fingerprint = %s, want %s", state.Fingerprint, schemaV3FreshFingerprint)
	}
	var marker string
	if err := db.QueryRow(`SELECT value FROM setting WHERE key=?`, keyP0Cutover).Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if marker != "schema3" {
		t.Fatalf("marker = %q", marker)
	}
}

func TestMigrateSchemaTwoToThreeBacksUpAndClearsLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2-to-v3.db")
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaTwo(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cipher.Encrypt("sk-cutover-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO upstream
		(name,base_url,api_key_enc,auth_style,full_url_mode,l1_path,probe_headers,created_at,updated_at)
		VALUES ('fixture','https://user:pass@full.example/v1/messages?x=1',?,'bearer',1,'',?,1,1)`,
		enc, `{"user-agent":"x"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO setting(key,value,updated_at) VALUES (?,?,1)`, keyProbeCost, `{"day":"x"}`); err != nil {
		t.Fatal(err)
	}

	result, err := migrateSchemaTwoToThree(context.Background(), db, path, cipher, MigrationBackupIdentity{
		PairedBuildID:  "p0-v2-test",
		ReaderContract: "schema-2-reader",
		CreatedAt:      time.Unix(456, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.SourceSchema != 2 || result.Manifest.TargetSchema != 3 {
		t.Fatalf("manifest = %+v", result.Manifest)
	}
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 3 {
		t.Fatalf("state = %+v", state)
	}
	var baseURL string
	var fullMode, enabled int
	var headers string
	if err := db.QueryRow(`SELECT base_url,full_url_mode,enabled,probe_headers FROM upstream WHERE id=1`).
		Scan(&baseURL, &fullMode, &enabled, &headers); err != nil {
		t.Fatal(err)
	}
	if fullMode != 0 {
		t.Fatalf("full_url_mode = %d", fullMode)
	}
	if headers != "" {
		t.Fatalf("probe_headers still set: %q", headers)
	}
	if baseURL != "https://full.example" {
		t.Fatalf("base_url = %q, want origin without userinfo/path", baseURL)
	}
	var costN int
	if err := db.QueryRow(`SELECT COUNT(*) FROM setting WHERE key=?`, keyProbeCost).Scan(&costN); err != nil {
		t.Fatal(err)
	}
	if costN != 0 {
		t.Fatalf("old cost key still present")
	}
}
