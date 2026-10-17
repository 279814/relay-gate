package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var backupSecretNames = []string{"keyring.json", "keyring.previous", "bootstrap-credentials.json", "credentials-bootstrap.journal", "credentials-migration.journal"}

func validBackupSecretName(name string) bool {
	for _, allowed := range backupSecretNames {
		if name == allowed {
			return true
		}
	}
	return false
}

func backupSecrets(dataDir, backupDir string, m *BackupManifest) error {
	secretDir := filepath.Join(dataDir, "secrets")
	if _, err := os.Lstat(secretDir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := rejectSymlinkOrReparse(secretDir); err != nil {
		return err
	}
	values := map[string][]byte{}
	for _, name := range backupSecretNames {
		path := filepath.Join(dataDir, "secrets", name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return errors.New("备份凭据文件类型或大小无效")
		}
		if err := rejectSymlinkOrReparse(path); err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		values[name] = raw
	}
	if len(values) == 0 {
		return nil
	} // env-managed deployments still pair by Master Key ID.
	raw, err := json.Marshal(values)
	if err != nil {
		return err
	}
	m.SecretsFile = "secrets.json"
	path := filepath.Join(backupDir, m.SecretsFile)
	if err := writeSyncedFile(path, raw, 0600); err != nil {
		return err
	}
	m.SecretsSize, m.SecretsSHA256, err = fileEvidence(path)
	return err
}

func readBackupSecrets(directory string, m *BackupManifest) (map[string][]byte, error) {
	if m.SecretsFile == "" {
		if m.SecretsSize != 0 || m.SecretsSHA256 != "" {
			return nil, errors.New("凭据备份元数据不完整")
		}
		return nil, nil
	}
	if m.SecretsFile != "secrets.json" || m.SecretsSize < 1 || m.SecretsSize > 8<<20 || m.SecretsSHA256 == "" {
		return nil, errors.New("凭据备份元数据无效")
	}
	path := filepath.Join(directory, m.SecretsFile)
	if err := rejectSymlinkOrReparse(path); err != nil {
		return nil, err
	}
	size, hash, err := fileEvidence(path)
	if err != nil {
		return nil, err
	}
	if size != m.SecretsSize || hash != m.SecretsSHA256 {
		return nil, errors.New("凭据备份文件证据不匹配")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string][]byte{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, errors.New("凭据备份结构无效")
	}
	for name, value := range values {
		if !validBackupSecretName(name) || len(value) > 1<<20 {
			return nil, errors.New("凭据备份名称或大小无效")
		}
	}
	if len(values) == 0 {
		return nil, errors.New("凭据备份为空")
	}
	return values, nil
}

func stageBackupSecrets(dataDir, backupDir string, m *BackupManifest) (string, error) {
	values, err := readBackupSecrets(backupDir, m)
	if err != nil || len(values) == 0 {
		return "", err
	}
	stage, err := os.MkdirTemp(dataDir, ".secrets-restore-")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(stage)
		}
	}()
	for name, raw := range values {
		if err := writeSyncedFile(filepath.Join(stage, name), raw, 0600); err != nil {
			return "", err
		}
	}
	if err := syncDirectory(stage); err != nil {
		return "", err
	}
	ok = true
	return stage, nil
}

func verifyInstalledSecrets(intent restoreIntent) error {
	if intent.SecretsStagingDirectory == "" {
		return nil
	}
	values, err := readBackupSecrets(filepath.Dir(intent.ManifestPath), &BackupManifest{SecretsFile: intent.SecretsFile, SecretsSize: intent.SecretsSize, SecretsSHA256: intent.SecretsSHA256})
	if err != nil {
		return err
	}
	for name, want := range values {
		path := filepath.Join(filepath.Dir(intent.DatabasePath), "secrets", name)
		if err := rejectSymlinkOrReparse(path); err != nil {
			return err
		}
		got, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("恢复的凭据文件 %s 与备份不匹配", name)
		}
	}
	return nil
}

// CipherFromBackupKeyring is used only for an explicit offline CLI opt-in.
// Archive and database evidence are checked before any archived master is
// selected. Keyring display IDs differ from the cipher's derived identifier;
// the actual active master must match the manifest, and pending is never guessed.
func CipherFromBackupKeyring(databasePath, manifestPath string) (*Cipher, error) {
	_, absManifest, backupDB, m, err := validateBackupPaths(databasePath, manifestPath)
	if err != nil {
		return nil, err
	}
	if err := verifyBackupEvidence(backupDB, m); err != nil {
		return nil, err
	}
	values, err := readBackupSecrets(filepath.Dir(absManifest), m)
	if err != nil {
		return nil, err
	}
	return cipherFromArchivedKeyring(values, m)
}

func cipherFromArchivedKeyring(values map[string][]byte, m *BackupManifest) (*Cipher, error) {
	raw := values["keyring.json"]
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: 备份不含已验证的 keyring.json", ErrRestoreRejected)
	}
	var root struct {
		FormatVersion int    `json:"format_version"`
		KeyID         string `json:"key_id"`
		Active        string `json:"active"`
		Pending       string `json:"pending"`
		Phase         string `json:"phase"`
		RotationID    string `json:"rotation_id"`
	}
	if err := json.Unmarshal(raw, &root); err != nil || root.FormatVersion != 1 || root.KeyID == "" || root.Active == "" || root.Pending != "" || (root.Phase == "" && root.RotationID != "") || (root.Phase != "" && root.Phase != "cleaned") {
		return nil, fmt.Errorf("%w: 归档 keyring 不是可恢复的稳定密钥根", ErrRestoreRejected)
	}
	c, err := NewCipher(root.Active)
	if err != nil {
		return nil, fmt.Errorf("%w: 归档 active Master 无效", ErrRestoreRejected)
	}
	if c.KeyID() != m.LegacyCipherID {
		return nil, fmt.Errorf("%w: 归档 active Master 与备份不配对", ErrRestoreRejected)
	}
	if err := validateArchivedCredentials(values, c, m.SourceSchema); err != nil {
		return nil, err
	}
	return c, nil
}

// The archive may contain credentials even when its Master is supplied by the
// environment. Validate the same v1 envelope contract without importing the
// credential service (which itself depends on Store).
func validateArchivedCredentials(values map[string][]byte, c *Cipher, sourceSchema int) error {
	raw, present := values["bootstrap-credentials.json"]
	if !present {
		return nil
	}
	var document *struct {
		FormatVersion int    `json:"format_version"`
		RelayKey      string `json:"relay_key"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document == nil || document.FormatVersion != 1 {
		return fmt.Errorf("%w: 归档持久凭据格式无效", ErrRestoreRejected)
	}
	relay := strings.TrimSpace(document.RelayKey)
	if relay == "" {
		return nil
	}
	if !strings.HasPrefix(relay, sampleEnvelopePrefix) {
		if sourceSchema < 8 {
			return nil // Historical readers still accept legacy plaintext.
		}
		return fmt.Errorf("%w: schema 8 归档 Relay Key 缺少认证信封", ErrRestoreRejected)
	}
	if _, err := c.cloneMasterCipher().DecryptEnvelope(relay); err != nil {
		return fmt.Errorf("%w: 归档 Relay Key 与备份 Master 不配对或密文损坏", ErrRestoreRejected)
	}
	return nil
}
