package store

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

// InsertSecurityFinding seals Detail under the independent Security Data Key.
// Callers still redact known credentials before this persistence boundary.
func (s *Store) InsertSecurityFinding(f security.Finding) error {
	if s == nil {
		return fmt.Errorf("store nil")
	}
	detail, err := s.cipher.encryptDataBlob(securityKeyPurpose, []byte(f.Detail))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO security_finding (
		id, at_ms, severity, category, summary, detail, upstream, route_id, req_id, source,
		scanner_version, rule_version, bytes_scanned, incomplete_reason, truncated, decode_depth, evidence_hash
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.ID, f.AtMS, string(f.Severity), f.Category, f.Summary, detail,
		f.Upstream, f.RouteID, f.ReqID, f.Source,
		f.ScannerVersion, f.RuleVersion, f.BytesScanned, f.IncompleteReason, f.Truncated, f.DecodeDepth, f.EvidenceHash,
	)
	return err
}

// ListSecurityFindings returns newest-first findings.
func (s *Store) ListSecurityFindings(severity string, limit int) ([]security.Finding, error) {
	if s == nil {
		return nil, fmt.Errorf("store nil")
	}
	limit, err := normalizePageLimit(limit)
	if err != nil {
		return nil, err
	}
	q := `SELECT id, at_ms, severity, category, summary, detail, upstream, route_id, req_id, source,
		scanner_version, rule_version, bytes_scanned, incomplete_reason, truncated, decode_depth, evidence_hash
		FROM security_finding`
	args := []any{}
	if severity != "" {
		q += ` WHERE severity=?`
		args = append(args, severity)
	}
	q += ` ORDER BY at_ms DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []security.Finding
	for rows.Next() {
		var f security.Finding
		var sev string
		if err := rows.Scan(&f.ID, &f.AtMS, &sev, &f.Category, &f.Summary, &f.Detail,
			&f.Upstream, &f.RouteID, &f.ReqID, &f.Source,
			&f.ScannerVersion, &f.RuleVersion, &f.BytesScanned, &f.IncompleteReason, &f.Truncated, &f.DecodeDepth, &f.EvidenceHash); err != nil {
			return nil, err
		}
		f.Severity = security.Severity(sev)
		if f.Detail != "" {
			plain, err := s.cipher.decryptDataBlob(securityKeyPurpose, []byte(f.Detail))
			if err != nil {
				return nil, fmt.Errorf("security evidence 解密失败")
			}
			f.Detail = string(plain)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CountSecurityFindings returns retained finding count.
func (s *Store) CountSecurityFindings() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM security_finding`).Scan(&n)
	return n, err
}

// SMTPConfig is the persisted alert mail settings (§13.6 / §14.6).
type SMTPConfig struct {
	Enabled              bool   `json:"enabled"`
	Host                 string `json:"host"`
	Port                 int    `json:"port"`
	UseSTARTTLS          bool   `json:"use_starttls"`
	UseSMTPS             bool   `json:"use_smtps"`
	From                 string `json:"from"`
	Recipients           string `json:"recipients"` // comma-separated
	Username             string `json:"username"`
	HasPassword          bool   `json:"has_password"`
	MinSeverity          string `json:"min_severity"`
	UpdatedAt            int64  `json:"updated_at"`
	AggregationWindowSec int    `json:"aggregation_window_sec"`
	RateLimitWindowSec   int    `json:"rate_limit_window_sec"`
	Revision             int64  `json:"revision"`
}

// GetSMTPConfig returns the singleton SMTP config (password never returned).
func (s *Store) GetSMTPConfig() (SMTPConfig, error) {
	c, _, err := s.readSMTPConfig()
	return c, err
}

// readSMTPConfig reads settings and their encrypted password in one SQLite snapshot.
func (s *Store) readSMTPConfig() (SMTPConfig, string, error) {
	var c SMTPConfig
	var en, starttls, smtps int
	var pw sql.NullString
	err := s.db.QueryRow(`SELECT enabled, host, port, use_starttls, use_smtps, from_addr, recipients,
		username, password_enc, min_severity, updated_at, aggregation_window_sec, rate_limit_window_sec, revision FROM smtp_config WHERE singleton=1`).
		Scan(&en, &c.Host, &c.Port, &starttls, &smtps, &c.From, &c.Recipients,
			&c.Username, &pw, &c.MinSeverity, &c.UpdatedAt, &c.AggregationWindowSec, &c.RateLimitWindowSec, &c.Revision)
	if err != nil {
		return c, "", err
	}
	c.Enabled = en != 0
	c.UseSTARTTLS = starttls != 0
	c.UseSMTPS = smtps != 0
	c.HasPassword = pw.Valid && len(pw.String) > 0
	if c.MinSeverity == "" {
		c.MinSeverity = "critical"
	}
	return c, pw.String, nil
}

// SMTPMailerConfig returns one consistent runtime snapshot; never log the password.
func (s *Store) SMTPMailerConfig() (security.MailConfig, error) {
	c, encrypted, err := s.readSMTPConfig()
	if err != nil {
		return security.MailConfig{}, err
	}
	password := ""
	if encrypted != "" {
		password, err = s.cipher.DecryptEnvelope(encrypted)
		if err != nil {
			return security.MailConfig{}, err
		}
	}
	recipients := make([]string, 0)
	for _, recipient := range strings.Split(c.Recipients, ",") {
		if recipient = strings.TrimSpace(recipient); recipient != "" {
			recipients = append(recipients, recipient)
		}
	}
	return security.MailConfig{
		Enabled: c.Enabled, Host: c.Host, Port: c.Port, UseSTARTTLS: c.UseSTARTTLS, UseSMTPS: c.UseSMTPS,
		From: c.From, Recipients: recipients, Username: c.Username, Password: password,
		MinSeverity: security.Severity(c.MinSeverity), AggregationWindowSec: c.AggregationWindowSec,
		RateLimitWindowSec: c.RateLimitWindowSec, Revision: c.Revision,
	}, nil
}

// SaveSMTPConfig updates settings only at the supplied Revision. An empty password keeps its ciphertext.
func (s *Store) SaveSMTPConfig(c SMTPConfig, passwordPlain string) error {
	if c.Revision < 1 || c.AggregationWindowSec < 1 || c.AggregationWindowSec > security.MaxSMTPWindowSec || c.RateLimitWindowSec < 1 || c.RateLimitWindowSec > security.MaxSMTPWindowSec {
		return fmt.Errorf("%w: SMTP revision 必须为正整数，聚合和限流窗口必须为 1–86400 秒", model.ErrValidation)
	}
	if c.Port == 0 {
		c.Port = 587
		if c.UseSMTPS {
			c.Port = 465
		}
	}
	if err := (security.MailConfig{Enabled: c.Enabled, Host: c.Host, Port: c.Port,
		UseSTARTTLS: c.UseSTARTTLS, UseSMTPS: c.UseSMTPS, From: c.From,
		Recipients: strings.Split(c.Recipients, ","), MinSeverity: security.Severity(c.MinSeverity), AggregationWindowSec: c.AggregationWindowSec, RateLimitWindowSec: c.RateLimitWindowSec}).Validate(); err != nil {
		return err
	}
	var pwSQL any
	keepPW := true
	if strings.TrimSpace(passwordPlain) != "" {
		enc, err := s.cipher.EncryptEnvelope(passwordPlain)
		if err != nil {
			return err
		}
		pwSQL = enc
		keepPW = false
	}
	en, st, sm := 0, 0, 0
	if c.Enabled {
		en = 1
	}
	if c.UseSTARTTLS {
		st = 1
	}
	if c.UseSMTPS {
		sm = 1
	}
	if c.MinSeverity == "" {
		c.MinSeverity = "critical"
	}
	now := nowMS()
	var result sql.Result
	var err error
	if !keepPW {
		result, err = s.db.Exec(`UPDATE smtp_config SET enabled=?, host=?, port=?, use_starttls=?, use_smtps=?,
   from_addr=?, recipients=?, username=?, password_enc=?, min_severity=?, updated_at=?, aggregation_window_sec=?, rate_limit_window_sec=?, revision=revision+1 WHERE singleton=1 AND revision=?`,
			en, c.Host, c.Port, st, sm, c.From, c.Recipients, c.Username, pwSQL, c.MinSeverity, now, c.AggregationWindowSec, c.RateLimitWindowSec, c.Revision)
	} else {
		result, err = s.db.Exec(`UPDATE smtp_config SET enabled=?, host=?, port=?, use_starttls=?, use_smtps=?,
   from_addr=?, recipients=?, username=?, min_severity=?, updated_at=?, aggregation_window_sec=?, rate_limit_window_sec=?, revision=revision+1 WHERE singleton=1 AND revision=?`,
			en, c.Host, c.Port, st, sm, c.From, c.Recipients, c.Username, c.MinSeverity, now, c.AggregationWindowSec, c.RateLimitWindowSec, c.Revision)
	}
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrRevisionConflict
	}
	return nil
}

// SMTPPasswordDecrypt returns the decrypted SMTP password for sending (caller must not log it).
func (s *Store) SMTPPasswordDecrypt() (string, error) {
	var enc sql.NullString
	err := s.db.QueryRow(`SELECT password_enc FROM smtp_config WHERE singleton=1`).Scan(&enc)
	if err != nil {
		return "", err
	}
	if !enc.Valid || enc.String == "" {
		return "", nil
	}
	return s.cipher.DecryptEnvelope(enc.String)
}
