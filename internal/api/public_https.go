package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

const publicHTTPSStatusLimit = 16 << 10

// publicHTTPSStatus deliberately excludes internal generation paths and all
// certificate/private-key bytes. A future edge field is not automatically an API.
type publicHTTPSStatus struct {
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
}

func (s *Server) WithPublicHTTPSStatusFile(path string) *Server {
	s.publicHTTPSStatusFile = path
	return s
}

func (s *Server) getPublicHTTPSStatus(w http.ResponseWriter, r *http.Request) {
	status, err := readPublicHTTPSStatus(s.publicHTTPSStatusFile)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"公网 HTTPS 状态暂不可用"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, status)
}

func readPublicHTTPSStatus(path string) (publicHTTPSStatus, error) {
	var status publicHTTPSStatus
	info, err := os.Lstat(path)
	if err != nil {
		return status, err
	}
	if !info.Mode().IsRegular() || info.Size() > publicHTTPSStatusLimit {
		return status, errors.New("invalid public status file")
	}
	file, err := os.Open(path)
	if err != nil {
		return status, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return status, errors.New("public status file changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, publicHTTPSStatusLimit+1))
	if err != nil {
		return status, err
	}
	if len(raw) > publicHTTPSStatusLimit || json.Unmarshal(raw, &status) != nil {
		return status, errors.New("invalid public status metadata")
	}
	address, err := netip.ParseAddr(status.IP)
	if err != nil || address.Zone() != "" || address.String() != status.IP || status.FormatVersion != 1 {
		return status, errors.New("invalid public status identity")
	}
	switch status.Phase {
	case "acme_only", "issuing", "validating", "live_https", "failed", "expired":
	default:
		return status, errors.New("invalid public status phase")
	}
	if len(status.LastError) > 512 || strings.ContainsAny(status.LastError, "\r\n\x00") {
		return status, errors.New("invalid public status error")
	}
	if status.CertificateFingerprint != "" {
		fingerprint, err := hex.DecodeString(status.CertificateFingerprint)
		if err != nil || len(fingerprint) != 32 {
			return status, errors.New("invalid public certificate fingerprint")
		}
	}
	for _, stamp := range []string{status.LastAttemptAt, status.LastSuccessAt, status.LastReloadAt} {
		if stamp != "" {
			if _, err := time.Parse(time.RFC3339, stamp); err != nil {
				return status, errors.New("invalid public status timestamp")
			}
		}
	}
	if status.NotAfter != "" {
		deadline, err := time.Parse(time.RFC3339, status.NotAfter)
		if err != nil {
			return status, errors.New("invalid public certificate expiry")
		}
		status.RemainingHours = time.Until(deadline).Hours()
		if status.RemainingHours <= 0 {
			status.Phase = "expired"
			status.BusinessAllowed = false
			status.AlertLowValidity = true
		}
	} else if status.BusinessAllowed {
		return status, errors.New("public status permits business without a certificate")
	}
	return status, nil
}
