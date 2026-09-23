package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Persisted is the on-disk credential material under data/secrets/ (§12.3 / §12.8).
// Admin password is stored only as Argon2id; never recoverable plaintext.
type Persisted struct {
	FormatVersion     int    `json:"format_version"`
	AdminPasswordHash string `json:"admin_password_hash"`
	RelayKey          string `json:"relay_key"`
	MasterKeyID       string `json:"master_key_id"`
	UpdatedAt         string `json:"updated_at"`
}

// SecretsDir returns dataDir/secrets.
func SecretsDir(dataDir string) string {
	return filepath.Join(dataDir, "secrets")
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
