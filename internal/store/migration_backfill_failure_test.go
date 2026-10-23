package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

var errAfterBackfillWrite = errors.New("fixture failure after backfill write")

// An error after the real write exercises rollback even when the caller cannot
// tell whether SQLite executed that statement. Only the test owns this wrapper.
type failingBackfillTransaction struct {
	*sql.Tx
	writes int
	failAt int
}

func (tx *failingBackfillTransaction) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, err := tx.Tx.ExecContext(ctx, query, args...)
	if err != nil {
		return result, err
	}
	tx.writes++
	if tx.writes == tx.failAt {
		return nil, errAfterBackfillWrite
	}
	return result, nil
}

func TestSchemaTwoBackfillRollsBackAfterEveryExecutedDML(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "backfill-failures.db")
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaOne(ctx, db); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher("backfill-failure-fixture-master")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt("fixture-backfill-only")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO upstream(id,name,base_url,api_key_enc,auth_style,full_url_mode,l1_path,created_at,updated_at) VALUES
	 (1,'base','https://fixture.invalid',?,'bearer',0,'/v1/models',1,1),
	 (2,'exact','https://fixture.invalid/v1/messages',?,'bearer',1,'/v1/models',1,1)`, encrypted, encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO model_name(id,name,protocol,created_at,updated_at) VALUES
	 (1,'anthropic-fixture','anthropic',1,1),(2,'responses-fixture','openai-responses',1,1),(3,'chat-fixture','openai-chat',1,1);
	 INSERT INTO route(id,model_name_id,upstream_id,created_at,updated_at) VALUES (1,1,1,1,1),(2,2,1,1,1),(3,3,1,1,1),(4,1,2,1,1)`); err != nil {
		t.Fatal(err)
	}
	before, err := inspectSchemaState(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	script, err := migrationFS.ReadFile("migrations/0002_p0_probe.sql")
	if err != nil {
		t.Fatal(err)
	}
	run := func(failAt int) (int, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return 0, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, string(script)); err != nil {
			return 0, err
		}
		writer := &failingBackfillTransaction{Tx: tx, failAt: failAt}
		if err := backfillSchemaTwo(ctx, writer, cipher); err != nil {
			return writer.writes, err
		}
		if err := validateForeignKeys(ctx, tx); err != nil {
			return writer.writes, err
		}
		return writer.writes, nil
	}
	writes, err := run(0)
	if err != nil || writes < 20 {
		t.Fatalf("fixture did not cover complete endpoint/recipe backfill: writes=%d err=%v", writes, err)
	}
	for failAt := 1; failAt <= writes; failAt++ {
		t.Run(fmt.Sprint("after-write-", failAt), func(t *testing.T) {
			got, err := run(failAt)
			if got != failAt || !errors.Is(err, errAfterBackfillWrite) {
				t.Fatalf("missed failure point: got=%d err=%v", got, err)
			}
			after, err := inspectSchemaState(ctx, db)
			if err != nil || after.Version != 1 || after.Fingerprint != before.Fingerprint {
				t.Fatalf("partial expansion escaped rollback: %+v %v", after, err)
			}
			var count int
			if err := db.QueryRow(`SELECT COUNT(*) FROM upstream WHERE api_key_enc=?`, encrypted).Scan(&count); err != nil || count != 2 {
				t.Fatalf("source ciphertext changed: count=%d err=%v", count, err)
			}
		})
	}
	t.Logf("verified rollback after all %d executed backfill DML statements", writes)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, cipher)
	if err != nil {
		t.Fatalf("restart could not migrate intact source: %v", err)
	}
	defer st.Close()
	var endpoints int
	// Canonical upstream: five endpoints. Single-protocol exact URL: only
	// models, messages and count_tokens; migration must not invent protocols.
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM upstream_endpoint`).Scan(&endpoints); err != nil || endpoints != 8 {
		t.Fatalf("restart endpoint backfill=%d err=%v", endpoints, err)
	}
}
