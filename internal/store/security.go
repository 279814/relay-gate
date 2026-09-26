package store

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/279814/relay-gate/internal/security"
)

// InsertSecurityFinding persists one finding (plain-text evidence only).
// Callers must already redact secrets from Detail (§14.5 / §16.4); this
// method stores the provided fields as-is.
func (s *Store) InsertSecurityFinding(f security.Finding) error {
	if s == nil {
		return fmt.Errorf("store nil")
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO security_finding (
		id, at_ms, severity, category, summary, detail, upstream, route_id, req_id, source,
		scanner_version, rule_version, bytes_scanned, incomplete_reason
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.ID, f.AtMS, string(f.Severity), f.Category, f.Summary, f.Detail,
		f.Upstream, f.RouteID, f.ReqID, f.Source,
		f.ScannerVersion, f.RuleVersion, f.BytesScanned, f.IncompleteReason,
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
		scanner_version, rule_version, bytes_scanned, incomplete_reason
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
			&f.ScannerVersion, &f.RuleVersion, &f.BytesScanned, &f.IncompleteReason); err != nil {
			return nil, err
		}
		f.Severity = security.Severity(sev)
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
	Enabled     bool   `json:"enabled"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	UseSTARTTLS bool   `json:"use_starttls"`
	UseSMTPS    bool   `json:"use_smtps"`
	From        string `json:"from"`
	Recipients  string `json:"recipients"` // comma-separated
	Username    string `json:"username"`
	HasPassword bool   `json:"has_password"`
	MinSeverity string `json:"min_severity"`
	UpdatedAt   int64  `json:"updated_at"`
}

// GetSMTPConfig returns the singleton SMTP config (password never returned).
func (s *Store) GetSMTPConfig() (SMTPConfig, error) {
	var c SMTPConfig
	var en, starttls, smtps int
	var pw sql.NullString
	err := s.db.QueryRow(`SELECT enabled, host, port, use_starttls, use_smtps, from_addr, recipients,
		username, password_enc, min_severity, updated_at FROM smtp_config WHERE singleton=1`).
		Scan(&en, &c.Host, &c.Port, &starttls, &smtps, &c.From, &c.Recipients,
			&c.Username, &pw, &c.MinSeverity, &c.UpdatedAt)
	if err != nil {
		return c, err
	}
	c.Enabled = en != 0
	c.UseSTARTTLS = starttls != 0
	c.UseSMTPS = smtps != 0
	c.HasPassword = pw.Valid && len(pw.String) > 0
	if c.MinSeverity == "" {
		c.MinSeverity = "critical"
	}
	return c, nil
}

// SaveSMTPConfig upserts SMTP settings. passwordPlain empty keeps existing password.
func (s *Store) SaveSMTPConfig(c SMTPConfig, passwordPlain string) error {
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
	if c.Port <= 0 {
		c.Port = 587
	}
	if c.MinSeverity == "" {
		c.MinSeverity = "critical"
	}
	now := nowMS()
	if !keepPW {
		_, err := s.db.Exec(`UPDATE smtp_config SET enabled=?, host=?, port=?, use_starttls=?, use_smtps=?,
			from_addr=?, recipients=?, username=?, password_enc=?, min_severity=?, updated_at=? WHERE singleton=1`,
			en, c.Host, c.Port, st, sm, c.From, c.Recipients, c.Username, pwSQL, c.MinSeverity, now)
		return err
	}
	_, err := s.db.Exec(`UPDATE smtp_config SET enabled=?, host=?, port=?, use_starttls=?, use_smtps=?,
		from_addr=?, recipients=?, username=?, min_severity=?, updated_at=? WHERE singleton=1`,
		en, c.Host, c.Port, st, sm, c.From, c.Recipients, c.Username, c.MinSeverity, now)
	return err
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
