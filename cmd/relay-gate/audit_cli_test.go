package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func TestCredentialsResetAdminCLIPersistsSuccessInTheSameAuditHistory(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("RELAY_DB", "")
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runMain([]string{"relay-gate", "credentials", "bootstrap", "--data-dir", dir}, strings.NewReader(""), io.Discard, &stderr); code != exitOK {
		t.Fatalf("bootstrap fixture failed: %s", stderr.String())
	}
	_, master, err := keyring.Open(dir).LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	cipher, _ := store.NewCipher(master)
	path := filepath.Join(dir, "relay-gate.db")
	st, err := store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if code := runMain([]string{"relay-gate", "credentials", "reset-admin", "--data-dir", dir}, strings.NewReader(""), &stdout, &stderr); code != exitOK {
		t.Fatalf("local reset failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "ADMIN_PASSWORD=") {
		t.Fatal("reset did not deliver the replacement password")
	}
	st, err = store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	page, err := st.ListAuditEventsPage(context.Background(), model.AuditEventFilter{Action: "admin_reset"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Outcome != "succeeded" {
		t.Fatalf("local reset bypassed persistent audit: page=%+v err=%v", page, err)
	}
	encoded, _ := json.Marshal(page.Items[0])
	password := strings.TrimPrefix(strings.SplitN(stdout.String(), "\n", 2)[0], "ADMIN_PASSWORD=")
	if strings.Contains(string(encoded), master) || strings.Contains(string(encoded), password) {
		t.Fatal("local audit retained plaintext credentials")
	}
}

func TestLocalAdminResetAuditFailureNeverChangesAnUnauditedPasswordOrRepeatsACompletedReset(t *testing.T) {
	for _, failure := range []string{"begin", "complete"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := (&credential.Bootstrap{DataDir: dir, Out: io.Discard}).Run(); err != nil {
				t.Fatal(err)
			}
			_, master, err := keyring.Open(dir).LoadActive()
			if err != nil {
				t.Fatal(err)
			}
			cipher, _ := store.NewCipher(master)
			st, err := store.Open(filepath.Join(dir, "relay-gate.db"), cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			before, err := credential.LoadAdminHash(dir)
			if err != nil {
				t.Fatal(err)
			}
			trigger := `CREATE TRIGGER deny_local_audit BEFORE INSERT ON audit_event WHEN NEW.action='admin_reset' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`
			if failure == "complete" {
				trigger = `CREATE TRIGGER deny_local_audit BEFORE UPDATE OF outcome ON audit_event WHEN NEW.action='admin_reset' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`
			}
			if _, err := st.DB().Exec(trigger); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := runAuditedAdminReset(st, dir, &stdout, &stderr)
			after, err := credential.LoadAdminHash(dir)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "begin" {
				if code != exitFail || before != after || stdout.Len() != 0 {
					t.Fatal("local reset changed credentials without durable audit")
				}
				return
			}
			password := strings.TrimPrefix(strings.SplitN(stdout.String(), "\n", 2)[0], "ADMIN_PASSWORD=")
			if code != exitOK || before == after || !credential.VerifyAdminPassword(password, after) || !strings.Contains(stderr.String(), "已完成，审计记录待确认") || !strings.Contains(stderr.String(), "勿重复") {
				t.Fatal("completed local reset was lost or reported retryable")
			}
			page, err := st.ListAuditEventsPage(context.Background(), model.AuditEventFilter{Action: "admin_reset"})
			if err != nil || len(page.Items) != 1 || page.Items[0].Outcome != "pending" {
				t.Fatal("terminal audit failure was misreported as a durable completion", err)
			}
		})
	}
}
