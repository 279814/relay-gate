package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/edge"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/store"
)

// WithCredentials wires credential + keyring services for the admin credentials page.
func (s *Server) WithCredentials(cred *credential.Service, keys *keyring.File) *Server {
	s.creds = cred
	s.keyring = keys
	return s
}

// WithRotationQuiescer connects the real proxy admission fence and background
// write barriers. The release handle is held until activation or a safe abort.
func (s *Server) WithRotationQuiescer(quiesce func(context.Context) (func(), error)) *Server {
	s.rotationQuiesce = quiesce
	return s
}

// WithMasterKeyEnvironmentOverride records startup configuration precedence.
// Rotation must not leave a new keyring paired with an older environment key.
func (s *Server) WithMasterKeyEnvironmentOverride(overridden bool) *Server {
	s.masterKeyEnvironmentOverride = overridden
	return s
}

const masterEnvironmentBlockedReason = "Master Key 仍由 ENCRYPTION_KEY 环境变量提供。请先运行 credentials migrate，移除旧 ENCRYPTION_KEY / RELAY_KEYS / ADMIN_PASSWORD 并重启，再进行轮换。"

func (s *Server) masterRotationAvailability() (bool, string) {
	if s.masterKeyEnvironmentOverride {
		return false, masterEnvironmentBlockedReason
	}
	if s.runState == nil || s.rotationQuiesce == nil || s.keyring == nil {
		return false, "轮换所需维护与写入收敛尚未装配"
	}
	if s.runState.InMaintenance() {
		return false, "维护中禁止重复触发 Master Key 轮换"
	}
	return true, ""
}

func (s *Server) getCredentialsStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Audit-Missed-Count", strconv.FormatUint(s.auditMissed.Load(), 10))
	if s.creds == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"credentials 未装配"})
		return
	}
	out := s.creds.Status()
	out["audit_missed_count"] = s.auditMissed.Load()
	page, err := s.st.ListAuditEventsPage(r.Context(), model.AuditEventFilter{PageRequest: model.PageRequest{Limit: 20}})
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"持久审计历史暂不可用"})
		return
	}
	out["audit"], out["audit_next_cursor"] = page.Items, page.NextCursor
	out["rotation_allowed"], out["blocked_reason"] = s.masterRotationAvailability()
	if s.keyring != nil {
		if st, err := s.keyring.Status(); err == nil {
			out["keyring"] = st
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) postRevealMasterKey(w http.ResponseWriter, r *http.Request) {
	if s.creds == nil || s.keyring == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"credentials 未装配"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if !s.passwordOK(body.Password) {
		s.writeErr(w, model.WrapValidation("管理员密码不正确"))
		return
	}
	_, master, err := s.keyring.LoadActive()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.creds.BeginMasterReveal(master, 30*time.Second)
	plain, err := s.creds.TakeMasterReveal()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"master_key": plain,
		"ttl_sec":    30,
		"note":       "短时显示；勿写入 localStorage / 前端日志",
	})
}

func (s *Server) postRevealRelayKey(w http.ResponseWriter, r *http.Request) {
	if s.creds == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"credentials 未装配"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if !s.passwordOK(body.Password) {
		writeJSON(w, http.StatusUnauthorized, errBody{"管理员密码不正确"})
		return
	}
	plain, err := s.creds.RevealActiveRelayKey()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"relay_key": plain,
		"note":      "当前 Key；重新认证后查看，勿写入 localStorage / 前端日志",
	})
}

func (s *Server) postRotateRelayKey(w http.ResponseWriter, r *http.Request) {
	if s.creds == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"credentials 未装配"})
		return
	}
	if s.runState != nil && s.runState.InMaintenance() {
		writeJSON(w, http.StatusConflict, map[string]any{
			"code":  runstate.MaintenanceActiveCode,
			"error": "maintenance 期间禁止凭据轮换",
		})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if !s.passwordOK(body.Password) {
		s.writeErr(w, model.WrapValidation("管理员密码不正确"))
		return
	}
	newKey, grace, err := s.creds.RotateRelayKey()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"relay_key":     newKey,
		"grace_seconds": grace,
		"note":          "新旧 Key 并存 grace 窗口；可立即撤销旧 Key",
	})
}

func (s *Server) postRevokeRelayGrace(w http.ResponseWriter, r *http.Request) {
	if s.creds == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"credentials 未装配"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if !s.passwordOK(body.Password) {
		s.writeErr(w, model.WrapValidation("管理员密码不正确"))
		return
	}
	if err := s.creds.RevokeGrace(); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) postResetAdminPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if !s.passwordOK(body.Password) {
		s.writeErr(w, model.WrapValidation("管理员密码不正确"))
		return
	}
	newPW, err := credential.GenerateAdminPassword()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	hash, err := credential.HashAdminPassword(newPW)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if s.adminDataDir != "" {
		if err := credential.ReplaceAdminHash(s.adminDataDir, hash); err != nil {
			s.writeErr(w, err)
			return
		}
	}
	s.adminHash = hash
	// 同进程 Bearer / 登录仍认新明文；不保留旧明文。不落盘可恢复明文。
	s.adminPW = newPW
	s.sessions.revokeAll()
	tok, err := s.sessions.issue()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: edge.IsHTTPS(r),
		MaxAge: int(sessionTTL.Seconds()),
	})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"admin_password": newPW,
		"note":           "仅此一次明文；之后不可查看，只能再重置",
	})
}

func (s *Server) postBeginMasterRotation(w http.ResponseWriter, r *http.Request) {
	if s.keyring == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"keyring 未装配"})
		return
	}
	if s.runState != nil && s.runState.InMaintenance() {
		writeJSON(w, http.StatusConflict, map[string]any{
			"code":  runstate.MaintenanceActiveCode,
			"error": "maintenance 期间禁止重复触发 Master Key 轮换",
		})
		return
	}
	var body struct {
		Password  string `json:"password"`
		NewMaster string `json:"new_master"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if !s.passwordOK(body.Password) {
		s.writeErr(w, model.WrapValidation("管理员密码不正确"))
		return
	}
	if len(body.NewMaster) < 16 {
		s.writeErr(w, model.WrapValidation("new_master 至少 16 字符"))
		return
	}
	if s.masterKeyEnvironmentOverride {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "master_key_environment_override", "error": masterEnvironmentBlockedReason})
		return
	}
	if s.runState == nil || s.rotationQuiesce == nil || s.creds == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"轮换所需维护与写入收敛尚未装配"})
		return
	}
	if err := s.runState.EnterMaintenance("master_key_rotation"); err != nil {
		if errors.Is(err, runstate.ErrMaintenanceActive) {
			writeJSON(w, http.StatusConflict, map[string]any{"code": runstate.MaintenanceActiveCode, "error": "轮换已在进行"})
		} else {
			s.writeErr(w, err)
		}
		return
	}
	exitMaintenance := true
	defer func() {
		if exitMaintenance {
			_ = s.runState.ExitMaintenance()
		}
	}()
	drainCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	releaseWrites, err := s.mutations.freeze(drainCtx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"管理写入尚未收敛，轮换未开始"})
		return
	}
	defer releaseWrites()
	releaseRuntime, err := s.rotationQuiesce(drainCtx)
	if err != nil || releaseRuntime == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"真实请求与后台写入尚未收敛，轮换未开始"})
		return
	}
	defer releaseRuntime()
	if err := s.startAuditOperation(r, r.Context(), "current"); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"审计暂不可用，轮换未开始"})
		return
	}
	_, oldMaster, err := s.keyring.LoadActive()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := validateRotationRelay(filepath.Dir(s.st.DatabasePath()), oldMaster); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.ValidateEncryptedState(); err != nil {
		s.writeErr(w, err)
		return
	}
	backup, err := s.st.CreateRotationBackup(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	backupCipher, err := store.NewCipher(oldMaster)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if _, err := store.CheckBackup(r.Context(), s.st.DatabasePath(), backup.ManifestPath, backupCipher); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.recordAuditStep(r, "master_rotation_backup"); err != nil {
		s.auditUnavailable(w, "master_rotation_backup", "step")
		writeJSON(w, http.StatusServiceUnavailable, errBody{"备份已创建，审计确认失败，轮换未开始"})
		return
	}
	rid, err := s.keyring.BeginRotation(body.NewMaster)
	if err != nil {
		status, statusErr := s.keyring.Status()
		exitMaintenance = statusErr == nil && (status.Phase == keyring.PhaseIdle || status.Phase == keyring.PhaseCleaned)
		s.writeErr(w, err)
		return
	}
	if err := s.st.RewrapDirectSecrets(body.NewMaster, rid); err != nil {
		// A failed Commit may have an uncertain outcome. Never discard the
		// only pending decryptor until SQLite proves this rotation uncommitted.
		committedID, inspectErr := store.CommittedMasterRotation(s.st.DatabasePath())
		if inspectErr != nil || committedID == rid {
			exitMaintenance = false
			setAuditResult(r, "unknown", "forward_recovery_required")
		} else if abortErr := s.keyring.AbortPrepared(rid); abortErr != nil {
			exitMaintenance = false
			setAuditResult(r, "failed", "rollback_failed")
		} else {
			setAuditResult(r, "failed", "rollback_completed")
		}
		s.writeErr(w, err)
		return
	}
	// From this point the database is committed under pending. Every failure
	// keeps maintenance and its journal; recovery may only roll forward.
	exitMaintenance = false
	setAuditResult(r, "unknown", "forward_recovery_required")
	if err := store.ValidateDatabaseEncryption(r.Context(), s.st.DatabasePath(), body.NewMaster); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.creds.ResealActiveRelayUnder(func(plain string) (string, error) {
		return store.SealEnvelopeUnder(body.NewMaster, plain)
	}); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := validateRotationRelay(filepath.Dir(s.st.DatabasePath()), body.NewMaster); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.keyring.MarkDBCommitted(rid); err != nil {
		s.writeErr(w, err)
		return
	}
	newID, err := s.keyring.ActivatePending(rid)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.ActivateMaster(body.NewMaster); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.ValidateEncryptedState(); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := validateRotationRelay(filepath.Dir(s.st.DatabasePath()), body.NewMaster); err != nil {
		s.writeErr(w, err)
		return
	}
	s.creds.ClearMasterReveal()
	if err := s.keyring.MarkCleaned(rid); err != nil {
		s.writeErr(w, err)
		return
	}
	s.st.ForgetRetiredMasterKeys()
	exitMaintenance = true
	setAuditResult(r, "succeeded", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"rotation_id":     rid,
		"new_key_id":      newID,
		"phase":           keyring.PhaseCleaned,
		"backup_manifest": backup.ManifestPath,
		"note":            "已验证一致备份、直接凭据与 Data Key 重封；样本正文保持原字节",
	})
}

func validateRotationRelay(dataDir, master string) error {
	doc, err := credential.LoadPersistedFile(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil // Legacy environment-only deployments have no persisted relay.
	}
	if err != nil {
		return err
	}
	if doc.FormatVersion != 1 {
		return errors.New("持久凭据格式无效，不能完成 Master Key 轮换")
	}
	if doc.RelayKey == "" {
		return nil
	}
	if !credential.IsRelayKeyEnvelope(doc.RelayKey) {
		return errors.New("持久 Relay Key 尚未加密，不能完成 Master Key 轮换")
	}
	cipher, err := store.NewCipher(master)
	if err != nil {
		return err
	}
	_, err = credential.OpenPersistedRelayKey(doc.RelayKey, cipher)
	return err
}

func (s *Server) passwordOK(got string) bool {
	if got == "" {
		return false
	}
	if s.adminHash != "" && credential.VerifyAdminPassword(got, s.adminHash) {
		return true
	}
	if s.adminPW == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.adminPW)) == 1
}
