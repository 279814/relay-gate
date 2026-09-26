package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Persisted is the on-disk credential material under data/secrets/ (§12.3 / §12.8).
// Admin password is stored only as Argon2id; never recoverable plaintext.
// RelayKey is a Master-Key envelope (v1:…) of the active Relay Key plaintext
// (§2.4 / §12.6); legacy installs may still hold recoverable plaintext until
// the next rotate/bootstrap rewrite. RelayGraceDigest is the SHA-256 hex of
// the previous active key during overlap; never store the previous raw key.
// RelayGraceUntil is RFC3339Nano UTC.
type Persisted struct {
	FormatVersion     int    `json:"format_version"`
	AdminPasswordHash string `json:"admin_password_hash"`
	RelayKey          string `json:"relay_key"`
	RelayGraceDigest  string `json:"relay_grace_digest,omitempty"`
	RelayGraceUntil   string `json:"relay_grace_until,omitempty"`
	MasterKeyID       string `json:"master_key_id"`
	UpdatedAt         string `json:"updated_at"`
}

// relayKeyEnvelopePrefix matches store.Cipher EncryptEnvelope (§12.4).
const relayKeyEnvelopePrefix = "v1:"

// IsRelayKeyEnvelope reports whether relay_key holds a Master-Key envelope.
func IsRelayKeyEnvelope(stored string) bool {
	return strings.HasPrefix(strings.TrimSpace(stored), relayKeyEnvelopePrefix)
}

// OpenPersistedRelayKey returns plaintext from an envelope or legacy plaintext
// dual-read (§2.4). Envelope rows require enc; legacy plaintext returns as-is.
func OpenPersistedRelayKey(stored string, enc EnvelopeCipher) (string, error) {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return "", nil
	}
	if !IsRelayKeyEnvelope(stored) {
		return stored, nil
	}
	if enc == nil {
		return "", errors.New("Relay Key 密文需要 Master Key 解密")
	}
	return enc.DecryptEnvelope(stored)
}

// SealPersistedRelayKey encrypts Relay Key plaintext for the relay_key field.
func SealPersistedRelayKey(plain string, enc EnvelopeCipher) (string, error) {
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return "", errors.New("relay key 不能为空")
	}
	if enc == nil {
		return "", errors.New("持久化 Relay Key 需要 Master Key 信封")
	}
	return enc.EncryptEnvelope(plain)
}

// SecretsDir returns dataDir/secrets.
func SecretsDir(dataDir string) string {
	return filepath.Join(dataDir, "secrets")
}

// ensureSecretsDir creates dataDir/secrets at 0700. MkdirAll does not change the
// mode of an existing directory, so always Chmod afterward (even on Windows,
// where the bits may not be enforced).
func ensureSecretsDir(dataDir string) error {
	dir := SecretsDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

// CredentialsFile returns the path of bootstrap/migration credential material.
func CredentialsFile(dataDir string) string {
	return filepath.Join(SecretsDir(dataDir), "bootstrap-credentials.json")
}

// HasAdminHash reports whether a non-empty Argon2id hash is on disk.
func HasAdminHash(dataDir string) bool {
	doc, err := LoadPersistedFile(dataDir)
	return err == nil && doc.AdminPasswordHash != ""
}

// ErrMigrationIncomplete tells the long-running server to refuse start until
// credentials migrate finishes (imported → completed).
var ErrMigrationIncomplete = errors.New("凭据未完成 migrate；请运行: relay-gate credentials migrate")

// RefuseIncompleteJournals blocks long-running start when a bootstrap or
// migration journal exists but has not reached its terminal phase (§12.3 / §12.8).
//
// Without this gate, credentials_persisted / imported artifacts under
// data/secrets/ would satisfy config.Load while plaintext was never delivered
// (or migration never completed) — leaving live Relay Keys and admin hashes
// the operator cannot recover except by guessing.
func RefuseIncompleteJournals(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	boot := &Bootstrap{DataDir: dataDir}
	bphase, err := boot.Phase()
	if err != nil {
		return err
	}
	if bphase != "" && bphase != PhaseDisplayed {
		return fmt.Errorf("%w（bootstrap journal 阶段=%s）", ErrBootstrapIncomplete, bphase)
	}
	mig := &Migration{DataDir: dataDir}
	mphase, err := mig.Phase()
	if err != nil {
		return err
	}
	if mphase != "" && mphase != MigPhaseCompleted {
		return fmt.Errorf("%w（migration journal 阶段=%s）", ErrMigrationIncomplete, mphase)
	}
	return nil
}

// LoadPersistedFile reads bootstrap-credentials.json without requiring journal phase.
func LoadPersistedFile(dataDir string) (Persisted, error) {
	raw, err := os.ReadFile(CredentialsFile(dataDir))
	if err != nil {
		return Persisted{}, err
	}
	var doc Persisted
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Persisted{}, fmt.Errorf("解析 credentials 文件: %w", err)
	}
	return doc, nil
}

// LoadAdminHash returns the Argon2id hash or an error if missing.
func LoadAdminHash(dataDir string) (string, error) {
	doc, err := LoadPersistedFile(dataDir)
	if err != nil {
		return "", err
	}
	if doc.AdminPasswordHash == "" {
		return "", ErrBootstrapIncomplete
	}
	return doc.AdminPasswordHash, nil
}

// ReplaceAdminHash updates only the admin password hash (reset-admin §12.5).
// Does not print or store plaintext. Preserves relay key and master key id.
func ReplaceAdminHash(dataDir string, hash string) error {
	if hash == "" {
		return errors.New("admin hash 不能为空")
	}
	doc, err := LoadPersistedFile(dataDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		doc = Persisted{FormatVersion: 1}
	}
	if doc.FormatVersion == 0 {
		doc.FormatVersion = 1
	}
	doc.AdminPasswordHash = hash
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeJSON0600(CredentialsFile(dataDir), doc)
}

// WritePersisted writes the full credentials file (0600).
func WritePersisted(dataDir string, doc Persisted) error {
	if doc.FormatVersion == 0 {
		doc.FormatVersion = 1
	}
	if doc.UpdatedAt == "" {
		doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return writeJSON0600(CredentialsFile(dataDir), doc)
}

// ReplaceRelayRotation updates the active relay_key envelope and optional grace
// digest/deadline after UI rotate (§12.6). sealedRelayKey must be a Master-Key
// envelope (or, for tests only, a value already prepared for the field).
// Preserves admin hash and master id. graceDigest must be the irreversible hex
// digest (never raw previous key).
func ReplaceRelayRotation(dataDir, sealedRelayKey, graceDigest string, graceUntil time.Time) error {
	if strings.TrimSpace(sealedRelayKey) == "" {
		return errors.New("relay key 不能为空")
	}
	doc, err := LoadPersistedFile(dataDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		doc = Persisted{FormatVersion: 1}
	}
	if doc.FormatVersion == 0 {
		doc.FormatVersion = 1
	}
	doc.RelayKey = sealedRelayKey
	if graceDigest != "" && !graceUntil.IsZero() {
		doc.RelayGraceDigest = graceDigest
		doc.RelayGraceUntil = graceUntil.UTC().Format(time.RFC3339Nano)
	} else {
		doc.RelayGraceDigest = ""
		doc.RelayGraceUntil = ""
	}
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeJSON0600(CredentialsFile(dataDir), doc)
}

// ReplacePersistedRelayKey rewrites only the sealed active Relay Key (Master
// Key rotation reseal). Preserves grace fields, admin hash, and master id.
func ReplacePersistedRelayKey(dataDir, sealedRelayKey string) error {
	if strings.TrimSpace(sealedRelayKey) == "" {
		return errors.New("relay key 不能为空")
	}
	doc, err := LoadPersistedFile(dataDir)
	if err != nil {
		return err
	}
	doc.RelayKey = sealedRelayKey
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeJSON0600(CredentialsFile(dataDir), doc)
}

// ClearPersistedRelayGrace drops overlapping grace fields after revoke or expiry.
func ClearPersistedRelayGrace(dataDir string) error {
	doc, err := LoadPersistedFile(dataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if doc.RelayGraceDigest == "" && doc.RelayGraceUntil == "" {
		return nil
	}
	doc.RelayGraceDigest = ""
	doc.RelayGraceUntil = ""
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeJSON0600(CredentialsFile(dataDir), doc)
}
