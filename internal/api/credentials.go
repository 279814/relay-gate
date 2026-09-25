package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
)

// WithCredentials wires credential + keyring services for the admin credentials page.
func (s *Server) WithCredentials(cred *credential.Service, keys *keyring.File) *Server {
	s.creds = cred
	s.keyring = keys
	return s
}

func (s *Server) getCredentialsStatus(w http.ResponseWriter, r *http.Request) {
	if s.creds == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"credentials 未装配"})
		return
	}
	out := s.creds.Status()
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
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
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
	if s.runState != nil {
		if err := s.runState.EnterMaintenance("master_key_rotation"); err != nil {
			if errors.Is(err, runstate.ErrMaintenanceActive) {
				writeJSON(w, http.StatusConflict, map[string]any{
					"code":  runstate.MaintenanceActiveCode,
					"error": err.Error(),
				})
				return
			}
			s.writeErr(w, err)
			return
		}
		exitMaint := true
		defer func() {
			if exitMaint {
				_ = s.runState.ExitMaintenance()
			}
		}()
		rid, err := s.keyring.BeginRotation(body.NewMaster)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		// §12.7 step 7: re-encrypt direct secrets under pending master in one TX
		// before MarkDBCommitted. Failure here aborts prepared (DB unchanged).
		if err := s.st.RewrapDirectSecrets(body.NewMaster); err != nil {
			_ = s.keyring.AbortPrepared(rid)
			s.writeErr(w, err)
			return
		}
		if err := s.keyring.MarkDBCommitted(rid); err != nil {
			// DB already under new master — keep pending + maintenance for recovery.
			exitMaint = false
			s.writeErr(w, err)
			return
		}
		newID, err := s.keyring.ActivatePending(rid)
		if err != nil {
			exitMaint = false // db_committed+：保持 maintenance 直至恢复（§12.7）
			s.writeErr(w, err)
			return
		}
		// Live Cipher must follow key_activated (same class as stale relay-key map).
		if err := s.st.ActivateMaster(body.NewMaster); err != nil {
			exitMaint = false
			s.writeErr(w, err)
			return
		}
		if s.creds != nil {
			if err := s.creds.ResealActiveRelayEnvelope(); err != nil {
				exitMaint = false
				s.writeErr(w, err)
				return
			}
			s.creds.ClearMasterReveal()
		}
		if err := s.keyring.MarkCleaned(rid); err != nil {
			exitMaint = false
			s.writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"rotation_id": rid,
			"new_key_id":  newID,
			"phase":       keyring.PhaseCleaned,
			"note":        "Keyring active 与 live Cipher 已切换；直接 Secret 与样本信封已重封",
		})
		return
	}
	rid, err := s.keyring.BeginRotation(body.NewMaster)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.RewrapDirectSecrets(body.NewMaster); err != nil {
		_ = s.keyring.AbortPrepared(rid)
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
	if s.creds != nil {
		if err := s.creds.ResealActiveRelayEnvelope(); err != nil {
			s.writeErr(w, err)
			return
		}
		s.creds.ClearMasterReveal()
	}
	if err := s.keyring.MarkCleaned(rid); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rotation_id": rid,
		"new_key_id":  newID,
		"phase":       keyring.PhaseCleaned,
		"note":        "Keyring active 与 live Cipher 已切换；直接 Secret 与样本信封已重封",
	})
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
