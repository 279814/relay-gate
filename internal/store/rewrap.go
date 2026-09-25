package store

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

// RewrapDirectSecrets re-encrypts Master-Key–sealed direct secrets under
// newMaster in one SQLite transaction (§12.7 step 7): upstream api_key,
// probe_secret, SMTP password, legacy_full_url, and enveloped sample body
// BLOBs. Legacy plaintext sample rows are left untouched (dual-read). Does
// not switch the live Cipher — caller ActivateMaster after Keyring
// key_activated. Failed rewrap rolls back the TX so activation never leaves
// half the samples on the old key.
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
	if err := rewrapSampleBodies(tx, s.cipher, newMaster); err != nil {
		return fmt.Errorf("rewrap sample: %w", err)
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

// rewrapSampleBodies reseals v1 sample body envelopes under newMaster.
// Plaintext rows stay as-is so dual-read history is not corrupted.
func rewrapSampleBodies(tx *sql.Tx, c *Cipher, newMaster string) error {
	rows, err := tx.Query(`SELECT id, in_body, out_body, resp_body FROM sample`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct {
		id            int64
		in, out, resp []byte
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.in, &r.out, &r.resp); err != nil {
			return err
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range batch {
		in, err := rewrapSampleField(c, newMaster, r.in)
		if err != nil {
			return fmt.Errorf("id=%d in_body: %w", r.id, err)
		}
		out, err := rewrapSampleField(c, newMaster, r.out)
		if err != nil {
			return fmt.Errorf("id=%d out_body: %w", r.id, err)
		}
		resp, err := rewrapSampleField(c, newMaster, r.resp)
		if err != nil {
			return fmt.Errorf("id=%d resp_body: %w", r.id, err)
		}
		if bytes.Equal(in, r.in) && bytes.Equal(out, r.out) && bytes.Equal(resp, r.resp) {
			continue
		}
		if _, err := tx.Exec(`UPDATE sample SET in_body=?, out_body=?, resp_body=? WHERE id=?`,
			in, out, resp, r.id); err != nil {
			return err
		}
	}
	return nil
}

func rewrapSampleField(c *Cipher, newMaster string, raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	if !IsSampleEnvelope(raw) && !isSampleMultipart(raw) {
		return raw, nil
	}
	plain, err := c.DecryptSampleBlob(raw)
	if err != nil {
		return nil, err
	}
	neu, err := encryptEnvelopeUnder(newMaster, string(plain))
	if err != nil {
		return nil, err
	}
	return []byte(neu), nil
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
