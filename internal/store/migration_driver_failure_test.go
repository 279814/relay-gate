package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"modernc.org/sqlite"
)

var errMigrationDriverBoundary = errors.New("synthetic migration driver boundary failure")

type migrationDriverEvent struct {
	kind      string
	committed bool
}

// Each disposable DB owns its connector and fault state. Neither the registered
// production driver nor a process-global production hook is replaced.
type migrationDriverFault struct {
	mu        sync.Mutex
	armed     bool
	failAt    int
	fired     bool
	events    []migrationDriverEvent
	committed bool
}

func (f *migrationDriverFault) after(kind, query string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.armed || f.fired {
		return nil
	}
	if kind == "exec" && strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(query), ";"), "COMMIT") {
		f.committed = true
	}
	f.events = append(f.events, migrationDriverEvent{kind: kind, committed: f.committed})
	if f.failAt == len(f.events) {
		f.fired = true
		return errMigrationDriverBoundary
	}
	return nil
}

type migrationFaultConnector struct {
	dsn   string
	base  sqlite.Driver
	fault *migrationDriverFault
}

func (c *migrationFaultConnector) Driver() driver.Driver { return &c.base }
func (c *migrationFaultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := c.base.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &migrationFaultConnection{Conn: conn, fault: c.fault}, nil
}

type migrationFaultConnection struct {
	driver.Conn
	fault *migrationDriverFault
}

func (c *migrationFaultConnection) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
	if err == nil {
		err = c.fault.after("exec", query)
	}
	return result, err
}

func (c *migrationFaultConnection) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	if err != nil {
		return nil, err
	}
	if err := c.fault.after("query", query); err != nil {
		_ = rows.Close()
		return nil, err
	}
	return rows, nil
}

func (c *migrationFaultConnection) NewBackup(destination string) (*sqlite.Backup, error) {
	return c.Conn.(sqliteBackupSource).NewBackup(destination)
}

func TestMigrationRunnerRecoversAfterEverySQLiteDriverBoundary(t *testing.T) {
	ctx := context.Background()
	cipher, err := NewCipher("migration-driver-fixture-master")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt("synthetic-migration-driver-value")
	if err != nil {
		t.Fatal(err)
	}
	identity := MigrationBackupIdentity{PairedBuildID: "driver-boundary-fixture", ReaderContract: "schema-1-reader", CreatedAt: time.Unix(123, 0)}
	fixture := func(t *testing.T, failAt int) (string, *sql.DB, *migrationDriverFault, inspectedSchemaState) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "driver-boundary.db")
		fault := &migrationDriverFault{failAt: failAt}
		db := sql.OpenDB(&migrationFaultConnector{dsn: path + connPragmas, fault: fault})
		t.Cleanup(func() { _ = db.Close() })
		if err := initializeEmptySchemaOne(ctx, db); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO upstream(id,name,base_url,api_key_enc,auth_style,full_url_mode,l1_path,created_at,updated_at) VALUES
		 (1,'base','https://fixture.invalid',?,'bearer',0,'/v1/models',1,1),
		 (2,'exact','https://fixture.invalid/v1/messages',?,'bearer',1,'/v1/models',1,1);
		 INSERT INTO model_name(id,name,protocol,created_at,updated_at) VALUES
		 (1,'anthropic-fixture','anthropic',1,1),(2,'responses-fixture','openai-responses',1,1),(3,'chat-fixture','openai-chat',1,1);
		 INSERT INTO route(id,model_name_id,upstream_id,created_at,updated_at) VALUES(1,1,1,1,1),(2,2,1,1,1),(3,3,1,1,1),(4,1,2,1,1)`, encrypted, encrypted); err != nil {
			t.Fatal(err)
		}
		before, err := inspectSchemaState(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		fault.armed = true
		return path, db, fault, before
	}
	path, db, baseline, _ := fixture(t, 0)
	if _, err := migrateSchemaOneToTwo(ctx, db, path, cipher, identity); err != nil {
		t.Fatal(err)
	}
	events := append([]migrationDriverEvent(nil), baseline.events...)
	_ = db.Close()
	var execs, queries int
	hasCommit := false
	for _, event := range events {
		hasCommit = hasCommit || event.committed
		if event.kind == "exec" {
			execs++
		} else {
			queries++
		}
	}
	if len(events) < 40 || !hasCommit {
		t.Fatalf("fixture missed the complete runner: events=%d", len(events))
	}
	for index, event := range events {
		t.Run(fmt.Sprintf("after-%d-%s", index+1, event.kind), func(t *testing.T) {
			path, db, fault, before := fixture(t, index+1)
			backup, err := migrateSchemaOneToTwo(ctx, db, path, cipher, identity)
			if err == nil || !fault.fired || len(fault.events) != index+1 || fault.events[index] != event {
				t.Fatalf("driver boundary not reached: fired=%v events=%d err=%v", fault.fired, len(fault.events), err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			// Inspect a physically reopened file through the normal registered
			// driver, so the fault wrapper cannot make recovery appear correct.
			reopened := openDatabaseAtPath(t, path)
			state, err := inspectSchemaState(ctx, reopened)
			if err != nil || (!event.committed && state != before) || (event.committed && state.Version != 2) {
				t.Fatalf("partial migration survived the failure: state=%+v err=%v", state, err)
			}
			var integrity string
			if err := reopened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
				t.Fatalf("reopened integrity=%q err=%v", integrity, err)
			}
			var backupHash string
			if backup.ManifestPath != "" {
				manifest, err := CheckBackup(ctx, path, backup.ManifestPath, cipher)
				if err != nil || manifest.SourceSchema != 1 || manifest.SourceFingerprint != before.Fingerprint {
					t.Fatalf("pre-DDL backup lost after driver failure: %v", err)
				}
				_, backupHash, err = fileEvidence(backup.DatabasePath)
				if err != nil {
					t.Fatal(err)
				}
			}
			if state.Version == 1 {
				if _, err := migrateSchemaOneToTwo(ctx, reopened, path, cipher, identity); err != nil {
					t.Fatalf("retry through production runner failed: %v", err)
				}
			}
			var count int
			if err := reopened.QueryRow(`SELECT COUNT(*) FROM upstream WHERE api_key_enc=?`, encrypted).Scan(&count); err != nil || count != 2 {
				t.Fatalf("source ciphertext lost: count=%d err=%v", count, err)
			}
			if err := reopened.QueryRow(`SELECT COUNT(*) FROM upstream_endpoint`).Scan(&count); err != nil || count != 8 {
				t.Fatalf("recovered endpoint mapping=%d err=%v", count, err)
			}
			if backupHash != "" {
				_, retainedHash, err := fileEvidence(backup.DatabasePath)
				if err != nil || retainedHash != backupHash {
					t.Fatal("retry overwrote the earlier backup generation")
				}
			}
			if index == 0 || index == len(events)/2 || event.committed {
				_ = reopened.Close()
				current, err := Open(path, cipher)
				if err != nil {
					t.Fatalf("normal startup could not finish the recovered migration: %v", err)
				}
				defer current.Close()
				state, err := inspectSchemaState(ctx, current.db)
				if err != nil || state.Version != developmentSchemaVersion {
					t.Fatalf("normal startup did not reach current schema: %+v %v", state, err)
				}
				if err := current.db.QueryRow(`SELECT COUNT(*) FROM upstream WHERE api_key_enc=?`, encrypted).Scan(&count); err != nil || count != 2 {
					t.Fatal("normal startup changed the recovered credentials")
				}
			}
		})
	}
	t.Logf("verified %d actual runner driver boundaries (%d exec, %d query) including validation and post-COMMIT uncertainty", len(events), execs, queries)
}
