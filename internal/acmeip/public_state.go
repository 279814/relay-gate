package acmeip

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PublicState contains only certificate/operation metadata. Private keys and
// unfiltered Certbot output are never serialized. API consumers omit the
// internal generation name and read only their explicit public field list.
type PublicState struct {
	FormatVersion          int     `json:"format_version"`
	IP                     string  `json:"ip"`
	Phase                  string  `json:"phase"`
	NotAfter               string  `json:"not_after"`
	RemainingHours         float64 `json:"remaining_hours"`
	LastAttemptAt          string  `json:"last_attempt_at"`
	LastSuccessAt          string  `json:"last_success_at"`
	LastReloadAt           string  `json:"last_reload_at"`
	LastError              string  `json:"last_error"`
	RenewAttempts          uint64  `json:"renew_attempts"`
	RenewSuccesses         uint64  `json:"renew_successes"`
	ReloadFailedKeepOld    bool    `json:"reload_failed_keep_old"`
	AlertLowValidity       bool    `json:"alert_low_validity"`
	BusinessAllowed        bool    `json:"business_allowed"`
	CertificateFingerprint string  `json:"certificate_fingerprint"`
	CurrentGeneration      string  `json:"current_generation,omitempty"`
}

func ReadPublicState(path string) (PublicState, error) {
	var state PublicState
	f, err := os.Open(path)
	if err != nil {
		return state, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if err != nil {
		return state, err
	}
	if len(raw) > 16<<10 {
		return state, errors.New("公网 HTTPS 状态文件超限")
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, errors.New("公网 HTTPS 状态格式无效")
	}
	if state.FormatVersion != 1 {
		return state, errors.New("不支持的公网 HTTPS 状态版本")
	}
	if _, err := ParsePublicIP(state.IP); err != nil {
		return state, err
	}
	if state.CurrentGeneration != "" && (state.CurrentGeneration == "." || state.CurrentGeneration == ".." || filepath.Base(state.CurrentGeneration) != state.CurrentGeneration || strings.ContainsAny(state.CurrentGeneration, "/\\\r\n\x00") || len(state.CurrentGeneration) > 96) {
		return state, errors.New("证书代际身份无效")
	}
	if state.CertificateFingerprint != "" {
		raw, err := hex.DecodeString(state.CertificateFingerprint)
		if err != nil || len(raw) != 32 {
			return state, errors.New("证书指纹格式无效")
		}
	}
	return state, nil
}

func writeAtomic(path string, raw []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".relay-public-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}
