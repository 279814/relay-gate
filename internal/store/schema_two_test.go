package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitializeEmptySchemaTwoCreatesP0CoreSchema(t *testing.T) {
	db := openSchemaTestDB(t, "empty-to-v2.db")
	if err := initializeEmptySchemaTwo(context.Background(), db); err != nil {
		t.Fatalf("initialize schema 2: %v", err)
	}
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil {
		t.Fatalf("inspect schema 2: %v", err)
	}
	if state.Version != 2 {
		t.Fatalf("state = %+v, want version 2", state)
	}

	for _, table := range []string{
		"run_state", "legacy_full_url", "upstream_endpoint", "probe_secret",
		"probe_recipe", "probe_recipe_version", "client_probe_profile",
		"probe_execution", "upstream_reachability", "endpoint_capability",
		"calibration_run", "calibration_candidate", "probe_cost_daily",
		"probe_cost_event", "probe_cost_retention_watermark", "observation_sequence",
	} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("table %s count = %d, want 1", table, count)
		}
	}
	for _, column := range []string{"probe_mode", "host_override", "tls_server_name", "revision", "network_revision", "credential_revision"} {
		has, err := hasColumn(db, "upstream", column)
		if err != nil {
			t.Fatal(err)
		}
		if !has {
			t.Errorf("upstream missing schema-2 column %s", column)
		}
	}
	for _, table := range []string{"model_name", "route"} {
		for _, column := range []string{"revision", "capability_revision"} {
			has, err := hasColumn(db, table, column)
			if err != nil {
				t.Fatal(err)
			}
			if !has {
				t.Errorf("%s missing schema-2 column %s", table, column)
			}
		}
	}
}

func TestApplySchemaTwoRollsBackAllDDLOnFailure(t *testing.T) {
	db := openSchemaTestDB(t, "schema-two-rollback.db")
	if err := initializeEmptySchemaOne(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	err := applySchemaTwo(context.Background(), db, []byte(`
		ALTER TABLE upstream ADD COLUMN temporary_v2_column TEXT NOT NULL DEFAULT '';
		CREATE TABLE broken (
	`))
	if err == nil {
		t.Fatal("invalid schema-2 migration must fail")
	}
	state, inspectErr := inspectSchemaState(context.Background(), db)
	if inspectErr != nil {
		t.Fatal(inspectErr)
	}
	if state.Version != 1 {
		t.Fatalf("failed migration changed schema version: %+v", state)
	}
	if has, hasErr := hasColumn(db, "upstream", "temporary_v2_column"); hasErr != nil || has {
		t.Fatalf("failed migration leaked DDL: has=%v err=%v", has, hasErr)
	}
}

func TestMigrateSchemaOneToTwoBacksUpBeforeDDL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1-to-v2.db")
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaOne(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt("sk-visible-only-after-decrypt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO upstream
		(name,base_url,api_key_enc,auth_style,created_at,updated_at)
		VALUES ('fixture','https://fixture.example',?,'bearer',1,1)`, encrypted); err != nil {
		t.Fatal(err)
	}

	result, err := migrateSchemaOneToTwo(context.Background(), db, path, cipher, MigrationBackupIdentity{
		PairedBuildID:  "pre-p0-test",
		ReaderContract: "schema-1-reader",
		CreatedAt:      time.Unix(123, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.SourceSchema != 1 || result.Manifest.TargetSchema != 2 {
		t.Fatalf("manifest = %+v", result.Manifest)
	}
	backupDB := openDatabaseAtPath(t, result.DatabasePath)
	backupState, err := inspectSchemaState(context.Background(), backupDB)
	if err != nil {
		t.Fatal(err)
	}
	if backupState.Version != 1 {
		t.Fatalf("backup state = %+v", backupState)
	}
	current, err := inspectSchemaState(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != 2 {
		t.Fatalf("current state = %+v", current)
	}
	if _, statErr := os.Stat(result.ManifestPath); statErr != nil {
		t.Fatalf("manifest not published: %v", statErr)
	}
}

func TestOpenUsesVersionedRunnerAndKeepsLifecycleLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "open-v2.db")
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	first, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	state, err := inspectSchemaState(context.Background(), first.db)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 2 {
		t.Fatalf("Open state = %+v, want schema 2", state)
	}
	if _, err := Open(path, cipher); !errors.Is(err, ErrInstanceLocked) {
		t.Fatalf("second Open error = %v, want ErrInstanceLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(path, cipher)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestKnownLegacyVariantsReachSchemaTwo(t *testing.T) {
	for _, variant := range []legacySchemaVariant{
		legacySchemaM2,
		legacySchemaM6PreColumn,
		legacySchemaM6PreIndex,
		legacySchemaM6Current,
	} {
		t.Run(string(variant), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "legacy.db")
			legacy := openDatabaseAtPath(t, path)
			loadLegacyVariantFixture(t, legacy, variant)
			if err := legacy.Close(); err != nil {
				t.Fatal(err)
			}
			cipher, err := NewCipher("test-passphrase-at-least-16-chars")
			if err != nil {
				t.Fatal(err)
			}
			st, err := Open(path, cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			state, err := inspectSchemaState(context.Background(), st.db)
			if err != nil {
				t.Fatal(err)
			}
			if state.Version != 2 {
				t.Fatalf("state = %+v", state)
			}
			manifests, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-*-to-*", "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(manifests) != 2 {
				t.Fatalf("backup manifests = %d, want one per boundary", len(manifests))
			}
		})
	}
}

func TestSchemaTwoBackfillBuildsCompleteLegacyRouteRecipes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-config.db")
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaOne(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt("sk-legacy-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO setting(key,value,updated_at) VALUES ('settings','{"probe_enabled":false}',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO upstream
		(id,name,base_url,api_key_enc,auth_style,full_url_mode,l1_path,probe_headers,created_at,updated_at)
		VALUES (1,'legacy','https://legacy.example',?,'bearer',0,'/custom-models',
		'{"x-custom":"keep-me","user-agent":"legacy-agent"}',1,1)`, encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO model_name
		(id,name,protocol,probe_prompt,probe_max_tokens,created_at,updated_at)
		VALUES (1,'claude-logical','anthropic','tiny prompt',7,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO route
		(id,model_name_id,upstream_id,upstream_model,created_at,updated_at)
		VALUES (1,1,1,'claude-upstream',1,1)`); err != nil {
		t.Fatal(err)
	}

	if _, err := migrateSchemaOneToTwo(context.Background(), db, path, cipher, MigrationBackupIdentity{
		PairedBuildID: "test", ReaderContract: "schema-1-reader",
	}); err != nil {
		t.Fatal(err)
	}
	var probeMode string
	if err := db.QueryRow(`SELECT probe_mode FROM upstream WHERE id=1`).Scan(&probeMode); err != nil {
		t.Fatal(err)
	}
	if probeMode != "lazy" {
		t.Fatalf("probe_mode = %q, want lazy", probeMode)
	}
	var endpointCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM upstream_endpoint WHERE upstream_id=1`).Scan(&endpointCount); err != nil {
		t.Fatal(err)
	}
	if endpointCount != 5 {
		t.Fatalf("endpoints = %d, want 5", endpointCount)
	}
	var authMode, modelsOverride string
	if err := db.QueryRow(`SELECT auth_mode FROM upstream_endpoint WHERE upstream_id=1 AND endpoint='messages'`).Scan(&authMode); err != nil {
		t.Fatal(err)
	}
	if authMode != "header_bearer" {
		t.Fatalf("messages auth_mode = %q", authMode)
	}
	if err := db.QueryRow(`SELECT url_override FROM upstream_endpoint WHERE upstream_id=1 AND endpoint='models'`).Scan(&modelsOverride); err != nil {
		t.Fatal(err)
	}
	if modelsOverride != "https://legacy.example/custom-models" {
		t.Fatalf("models override = %q", modelsOverride)
	}

	rows, err := db.Query(`SELECT r.endpoint, r.status, v.origin, v.headers_json, CAST(v.body AS TEXT)
		FROM probe_recipe r JOIN probe_recipe_version v ON v.id=r.published_version_id
		WHERE r.route_id=1 ORDER BY r.endpoint`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := map[string]string{}
	for rows.Next() {
		var endpoint, status, origin, headersRaw, body string
		if err := rows.Scan(&endpoint, &status, &origin, &headersRaw, &body); err != nil {
			t.Fatal(err)
		}
		if status != "legacy_compat" || origin != "legacy_migration" {
			t.Fatalf("%s status/origin = %s/%s", endpoint, status, origin)
		}
		var headers []map[string]any
		if err := json.Unmarshal([]byte(headersRaw), &headers); err != nil {
			t.Fatalf("%s headers: %v", endpoint, err)
		}
		if !strings.Contains(strings.ToLower(headersRaw), "x-custom") || !strings.Contains(headersRaw, "legacy-agent") {
			t.Fatalf("%s lost upstream headers: %s", endpoint, headersRaw)
		}
		found[endpoint] = body
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"messages", "count_tokens"} {
		body, ok := found[endpoint]
		if !ok {
			t.Fatalf("missing route recipe %s; found=%v", endpoint, found)
		}
		if !strings.Contains(body, "{{UPSTREAM_MODEL}}") || !strings.Contains(body, "{{PROBE_PROMPT}}") {
			t.Fatalf("%s body lost placeholders: %s", endpoint, body)
		}
	}
	if !strings.Contains(found["messages"], `"max_tokens":7`) {
		t.Fatalf("messages max_tokens lost: %s", found["messages"])
	}
}

func TestSchemaTwoBackfillPreservesLegacyFullURLAsEncryptedRealCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-full-url.db")
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaOne(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	keyEnc, err := cipher.Encrypt("sk-legacy-key")
	if err != nil {
		t.Fatal(err)
	}
	const exactURL = "https://legacy.example/prefix/v1/messages?token=low-entropy-secret&x=1"
	if _, err := db.Exec(`INSERT INTO upstream
		(id,name,base_url,api_key_enc,auth_style,full_url_mode,l1_path,created_at,updated_at)
		VALUES (1,'legacy-full',?,?,'auto',1,'/v1/models',1,1)`, exactURL, keyEnc); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO model_name(id,name,protocol,created_at,updated_at) VALUES
		(1,'claude','anthropic',1,1),(2,'gpt','openai-responses',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO route(id,model_name_id,upstream_id,created_at,updated_at) VALUES
		(1,1,1,1,1),(2,2,1,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateSchemaOneToTwo(context.Background(), db, path, cipher, MigrationBackupIdentity{
		PairedBuildID: "test", ReaderContract: "schema-1-reader",
	}); err != nil {
		t.Fatal(err)
	}
	var baseURL string
	var fullURLMode bool
	if err := db.QueryRow(`SELECT base_url,full_url_mode FROM upstream WHERE id=1`).Scan(&baseURL, &fullURLMode); err != nil {
		t.Fatal(err)
	}
	if baseURL != exactURL || !fullURLMode {
		t.Fatalf("legacy columns changed: base=%q full=%v", baseURL, fullURLMode)
	}
	var urlEnc, masked, fingerprint string
	var inferred *string
	if err := db.QueryRow(`SELECT url_enc,masked_url,fingerprint,inferred_endpoint FROM legacy_full_url WHERE upstream_id=1`).
		Scan(&urlEnc, &masked, &fingerprint, &inferred); err != nil {
		t.Fatal(err)
	}
	plain, err := cipher.Decrypt(urlEnc)
	if err != nil || plain != exactURL {
		t.Fatalf("encrypted exact URL = %q, err=%v", plain, err)
	}
	if strings.Contains(masked, "token=") || !strings.HasPrefix(fingerprint, cipher.KeyID()+":") || inferred != nil {
		t.Fatalf("unsafe legacy metadata: masked=%q fingerprint=%q inferred=%v", masked, fingerprint, inferred)
	}
	rows, err := db.Query(`SELECT endpoint,url_mode,legacy_compat_real_only,needs_review,auth_mode
		FROM upstream_endpoint WHERE upstream_id=1 ORDER BY endpoint`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]string{}
	for rows.Next() {
		var endpoint, mode, auth string
		var realOnly, review bool
		if err := rows.Scan(&endpoint, &mode, &realOnly, &review, &auth); err != nil {
			t.Fatal(err)
		}
		seen[endpoint] = mode
		if auth != "legacy_auto_real_only" || !realOnly {
			t.Fatalf("%s legacy auto flags: auth=%s realOnly=%v", endpoint, auth, realOnly)
		}
		if endpoint != "models" && !review {
			t.Fatalf("%s legacy exact endpoint must need review", endpoint)
		}
	}
	for _, endpoint := range []string{"messages", "count_tokens", "responses"} {
		if seen[endpoint] != "legacy_exact" {
			t.Fatalf("%s mode = %q; all=%v", endpoint, seen[endpoint], seen)
		}
	}
	if seen["models"] != "canonical" {
		t.Fatalf("models mode = %q", seen["models"])
	}
}

func openDatabaseAtPath(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path+connPragmas)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
