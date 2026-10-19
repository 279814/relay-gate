package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/store"
)

func localAuditActor(source string) string {
	sum := sha256.Sum256([]byte("relay-gate:audit-actor:v1:local:" + source))
	return hex.EncodeToString(sum[:])
}

func openCredentialAuditStore(dataDir, path string, held *store.InstanceLock) (*store.Store, error) {
	master := strings.TrimSpace(os.Getenv("ENCRYPTION_KEY"))
	if master == "" {
		var err error
		_, master, err = keyring.Open(dataDir).LoadActive()
		if err != nil {
			return nil, err
		}
	}
	cipher, err := store.NewCipher(master)
	if err != nil {
		return nil, err
	}
	buildID, err := store.CurrentReaderBuildID(version)
	if err != nil {
		return nil, err
	}
	return store.OpenLockedWithReaderBuildID(path, cipher, held, buildID)
}

func runAuditedAdminReset(st *store.Store, dataDir string, stdout, stderr io.Writer) int {
	ctx := context.Background()
	id, err := st.BeginAuditEvent(ctx, "admin_reset", "current", localAuditActor("credentials-cli"))
	if err != nil {
		fmt.Fprintln(stderr, "credentials reset-admin 未执行：持久审计不可用")
		return exitFail
	}
	// The returned password is bounded generated data, not an arbitrary body.
	// Finish audit before its one-time display whenever the database permits.
	password, err := credential.ResetAdmin(dataDir, io.Discard)
	if err != nil {
		if auditErr := st.CompleteAuditEvent(ctx, id, "failed", "operation_failed"); auditErr != nil {
			fmt.Fprintf(stderr, "reset-admin 未完成，失败审计待确认（事件 #%d）。\n", id)
		}
		fmt.Fprintf(stderr, "credentials reset-admin 失败: %v\n", err)
		return exitFail
	}
	auditErr := st.CompleteAuditEvent(ctx, id, "succeeded", "")
	fmt.Fprintf(stdout, "ADMIN_PASSWORD=%s\n", password)
	fmt.Fprintln(stdout, "# 新管理员密码仅显示一次；旧密码不可恢复、未打印。")
	if auditErr != nil {
		fmt.Fprintf(stderr, "reset-admin 已完成，审计记录待确认（事件 #%d）；请勿重复执行。\n", id)
	}
	fmt.Fprintln(stderr, "credentials reset-admin 完成（新密码仅上方显示一次）。")
	return exitOK
}

// Crypto recovery must establish a usable active cipher before Store.Open.
// Record its observed result afterwards; auditing never repeats or drives it.
func recordRotationRecoveryAudit(st *store.Store, before, after keyring.Status) error {
	if before.Phase != keyring.PhasePrepared && before.Phase != keyring.PhaseDBCommitted && before.Phase != keyring.PhaseKeyActivated {
		return nil
	}
	action, outcome, reason := "master_recovery", "succeeded", ""
	if before.Phase == keyring.PhasePrepared && after.Phase == keyring.PhaseIdle {
		action = "master_rotation_rollback"
	} else if after.HasPending || after.Phase != keyring.PhaseCleaned {
		outcome, reason = "unknown", "forward_recovery_required"
	}
	id, err := st.BeginAuditEvent(context.Background(), action, "current", localAuditActor("startup"))
	if err != nil {
		return err
	}
	return st.CompleteAuditEvent(context.Background(), id, outcome, reason)
}
