package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

// RewrapDirectSecrets re-encrypts Master-Key–sealed direct secrets under
// newMaster in one SQLite transaction (§12.7 step 7): upstream api_key,
// probe_secret, SMTP password, and legacy_full_url. Does not switch the live
// Cipher — caller ActivateMaster after Keyring key_activated. Sample body
// envelopes are not rewritten (§5.4).
func (s *Store) RewrapDirectSecrets(newMaster string) error {
	if s == nil || s.cipher == nil {
		return ErrNoKey
	}
	if _, _, err := deriveMaster(newMaster); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := rewrapUpstreamKeys(tx, s.cipher, newMaster); err != nil {
		return fmt.Errorf("rewrap upstream: %w", err)
	}
	if err := rewrapProbeSecrets(tx, s.cipher, newMaster); err != nil {
		return fmt.Errorf("rewrap probe_secret: %w", err)
	}
	if err := rewrapSMTPPassword(tx, s.cipher, newMaster); err != nil {
		return fmt.Errorf("rewrap smtp: %w", err)
	}
	if err := rewrapLegacyURLs(tx, s.cipher, newMaster); err != nil {
		return fmt.Errorf("rewrap legacy_full_url: %w", err)
	}
	return tx.Commit()
}

func rewrapUpstreamKeys(tx *sql.Tx, c *Cipher, newMaster string) error {
	rows, err := tx.Query(`SELECT id, api_key_enc FROM upstream`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct {
		id  int64
		enc string
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.enc); err != nil {
			return err
		}
		if r.enc == "" {
			continue
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range batch {
		plain, err := c.Decrypt(r.enc)
		if err != nil {
			return fmt.Errorf("id=%d: %w", r.id, err)
		}
		neu, err := encryptUnder(newMaster, plain)
		if err != nil {
			return fmt.Errorf("id=%d: %w", r.id, err)
		}
		if _, err := tx.Exec(`UPDATE upstream SET api_key_enc=? WHERE id=?`, neu, r.id); err != nil {
			return err
		}
	}
	return nil
}

func rewrapProbeSecrets(tx *sql.Tx, c *Cipher, newMaster string) error {
	rows, err := tx.Query(`SELECT id, value_enc FROM probe_secret`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct {
		id  int64
		enc string
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.enc); err != nil {
			return err
		}
		if r.enc == "" {
			continue
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range batch {
		plain, err := c.Decrypt(r.enc)
		if err != nil {
			return fmt.Errorf("id=%d: %w", r.id, err)
		}
		neu, err := encryptUnder(newMaster, plain)
		if err != nil {
			return fmt.Errorf("id=%d: %w", r.id, err)
		}
		fp, err := fingerprintUnder(newMaster, "probe-secret", []byte(plain))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE probe_secret SET value_enc=?, fingerprint=? WHERE id=?`,
			neu, fp, r.id); err != nil {
			return err
		}
	}
	return nil
}

func rewrapSMTPPassword(tx *sql.Tx, c *Cipher, newMaster string) error {
	var enc sql.NullString
	err := tx.QueryRow(`SELECT password_enc FROM smtp_config WHERE singleton=1`).Scan(&enc)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if !enc.Valid || enc.String == "" {
		return nil
	}
	plain, err := c.DecryptEnvelope(enc.String)
	if err != nil {
		return err
	}
	neu, err := encryptEnvelopeUnder(newMaster, plain)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE smtp_config SET password_enc=? WHERE singleton=1`, neu)
	return err
}

func rewrapLegacyURLs(tx *sql.Tx, c *Cipher, newMaster string) error {
	rows, err := tx.Query(`SELECT id, url_enc FROM legacy_full_url`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct {
		id  int64
		enc string
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.enc); err != nil {
			return err
		}
		if r.enc == "" {
			continue
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range batch {
		plain, err := c.Decrypt(r.enc)
		if err != nil {
			return fmt.Errorf("id=%d: %w", r.id, err)
		}
		neu, err := encryptUnder(newMaster, plain)
		if err != nil {
			return fmt.Errorf("id=%d: %w", r.id, err)
		}
		fp, err := fingerprintUnder(newMaster, "legacy-full-url", []byte(plain))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE legacy_full_url SET url_enc=?, fingerprint=? WHERE id=?`,
			neu, fp, r.id); err != nil {
			return err
		}
	}
	return nil
}

func encryptUnder(passphrase, plain string) (string, error) {
	aead, _, err := deriveMaster(passphrase)
	if err != nil {
		return "", err
	}
	return encryptWith(aead, plain)
}

func encryptEnvelopeUnder(passphrase, plain string) (string, error) {
	aead, root, err := deriveMaster(passphrase)
	if err != nil {
		return "", err
	}
	inner, err := encryptWith(aead, plain)
	if err != nil {
		return "", err
	}
	return sampleEnvelopePrefix + keyIDOf(root) + ":" + inner, nil
}

func fingerprintUnder(passphrase, kind string, plain []byte) (string, error) {
	_, root, err := deriveMaster(passphrase)
	if err != nil {
		return "", err
	}
	derive := hmac.New(sha256.New, root[:])
	_, _ = derive.Write([]byte("relay-gate/hmac-key/v1\x00fingerprint/" + kind))
	subkey := derive.Sum(nil)
	digest := hmac.New(sha256.New, subkey)
	_, _ = digest.Write(plain)
	return keyIDOf(root) + ":" + hex.EncodeToString(digest.Sum(nil)), nil
}
