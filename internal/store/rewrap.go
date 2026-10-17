package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// RewrapDirectSecrets re-encrypts Master-Key–sealed direct secrets under
// newMaster in one SQLite transaction (§12.7 step 7): upstream api_key,
// probe_secret, SMTP password, legacy_full_url, and the two Data Key wrappers.
// Sample/security body ciphertext stays byte-for-byte unchanged. The entire
// state must decrypt with the pending master alone before the TX can commit.
// The caller activates the live Cipher only after the Keyring advances.
//
// rotationID is written in the same TX (§12.7 step 7) so startup recovery can
// tell "prepared, DB not committed" (abort) from "prepared, DB committed"
// (roll forward): aborting after this commit would discard the only key the
// rows open under.
func (s *Store) RewrapDirectSecrets(newMaster, rotationID string) error {
	if s == nil || s.cipher == nil {
		return ErrNoKey
	}
	if strings.TrimSpace(rotationID) == "" {
		return fmt.Errorf("rewrap 需要 rotation_id")
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
	if err := rewrapDataKeys(tx, s.cipher, newMaster); err != nil {
		return fmt.Errorf("rewrap Data Key: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO setting (key, value, updated_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		keyMasterRotation, rotationID, nowMS()); err != nil {
		return fmt.Errorf("rewrap rotation_id: %w", err)
	}
	pending, err := NewCipher(newMaster)
	if err != nil {
		return err
	}
	keys, err := readDataKeys(context.Background(), tx, pending)
	if err != nil {
		return err
	}
	pending.installDataKeys(keys)
	if err := validateEncryptedState(context.Background(), tx, pending); err != nil {
		return err
	}
	return tx.Commit()
}

func rewrapDataKeys(tx *sql.Tx, current *Cipher, newMaster string) error {
	rows, err := tx.Query(`SELECT purpose,wrapped_key FROM data_key ORDER BY purpose`)
	if err != nil {
		return err
	}
	type value struct{ purpose, wrapped string }
	var values []value
	for rows.Next() {
		var v value
		if err := rows.Scan(&v.purpose, &v.wrapped); err != nil {
			rows.Close()
			return err
		}
		values = append(values, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(values) != 2 {
		return errors.New("Data Key 包装不完整")
	}
	for _, v := range values {
		plain, err := current.DecryptEnvelope(v.wrapped)
		if err != nil {
			return err
		}
		wrapped, err := encryptEnvelopeUnder(newMaster, plain)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE data_key SET wrapped_key=? WHERE purpose=?`, wrapped, v.purpose); err != nil {
			return err
		}
	}
	return nil
}

const keyMasterRotation = "master_rotation_id"

// CommittedMasterRotation returns the rotation_id last committed by
// RewrapDirectSecrets in the SQLite file at dbPath, or "" when the file, the
// setting table, or the row is absent. Startup calls it before the Store is
// opened (the live Cipher depends on which key recovery leaves active).
func CommittedMasterRotation(dbPath string) (string, error) {
	path := dbPathOf(dbPath)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	db, err := sql.Open("sqlite", path+connPragmas)
	if err != nil {
		return "", err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='setting'`).Scan(&n); err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	var rid string
	err = db.QueryRow(`SELECT value FROM setting WHERE key=?`, keyMasterRotation).Scan(&rid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return rid, err
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

// SealEnvelopeUnder builds a v1 envelope under passphrase without switching
// the live Cipher. Used during Master Key rotation (§12.7 step 7) so the
// persisted Relay Key can be resealed under pending before ActivatePending
// drops the old active key.
func SealEnvelopeUnder(passphrase, plain string) (string, error) {
	return encryptEnvelopeUnder(passphrase, plain)
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
