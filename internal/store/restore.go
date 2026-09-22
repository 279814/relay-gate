package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	restoreIntentFileName = "restore-intent.json"
	restoreIntentVersion  = 1

	restorePhasePrepared  = "prepared"
	restorePhaseIsolated  = "isolated"
	restorePhaseInstalled = "installed"
	restorePhaseComplete  = "complete"
)

var (
	ErrRestoreRejected = errors.New("restore rejected")
	ErrRestorePending  = errors.New("incomplete restore intent")
)

// RestoreResult is the verified DTO returned to the offline CLI.
type RestoreResult struct {
	RestoredSchemaVersion int    `json:"restored_schema_version"`
	PairedBuildID         string `json:"paired_build_id"`
	ReaderContract        string `json:"reader_contract"`
	IsolationDirectory    string `json:"isolation_directory"`
	DataLossBoundary      string `json:"data_loss_boundary"`
}

type restoreIntent struct {
	FormatVersion      int    `json:"format_version"`
	Phase              string `json:"phase"`
	DatabasePath       string `json:"database_path"`
	ManifestPath       string `json:"manifest_path"`
	BackupDatabasePath string `json:"backup_database_path"`
	StagingPath        string `json:"staging_path"`
	IsolationDirectory string `json:"isolation_directory"`
	DatabaseSHA256     string `json:"database_sha256"`
	DatabaseSize       int64  `json:"database_size"`
	SourceSchema       int    `json:"source_schema"`
	PairedBuildID      string `json:"paired_build_id"`
	ReaderContract     string `json:"reader_contract"`
	LegacyCipherID     string `json:"legacy_cipher_id"`
	UpdatedAt          string `json:"updated_at"`
}

// CheckBackup validates a migration backup without moving any files.
func CheckBackup(ctx context.Context, databasePath, manifestPath string, cipher *Cipher) (*BackupManifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cipher == nil {
		return nil, ErrNoKey
	}
	absDB, absManifest, backupDB, manifest, err := validateBackupPaths(databasePath, manifestPath)
	if err != nil {
		return nil, err
	}
	_ = absDB
	if err := verifyBackupEvidence(backupDB, manifest); err != nil {
		return nil, err
	}
	if manifest.LegacyCipherID != cipher.KeyID() {
		return nil, fmt.Errorf("%w: cipher ID 与 manifest 不匹配", ErrRestoreRejected)
	}
	if err := validateBackupDatabase(ctx, backupDB, cipher, manifest); err != nil {
		return nil, err
	}
	_ = absManifest
	out := *manifest
	return &out, nil
}

// RestoreDatabase replaces the live database with a verified migration backup.
// Missing destructive authorizations return ErrRestoreRejected with zero file moves.
func RestoreDatabase(ctx context.Context, databasePath, manifestPath string, cipher *Cipher, acceptDataReplacement bool, acceptedReaderContract string) (*RestoreResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cipher == nil {
		return nil, ErrNoKey
	}
	if !acceptDataReplacement {
		return nil, fmt.Errorf("%w: 需要 --accept-data-replacement", ErrRestoreRejected)
	}
	absDB, absManifest, backupDB, manifest, err := validateBackupPaths(databasePath, manifestPath)
	if err != nil {
		return nil, err
	}
	if acceptedReaderContract == "" || acceptedReaderContract != manifest.ReaderContract {
		return nil, fmt.Errorf("%w: --accept-reader-contract 必须与 check-backup 输出的 ReaderContract 完全一致", ErrRestoreRejected)
	}
	if manifest.LegacyCipherID != cipher.KeyID() {
		return nil, fmt.Errorf("%w: cipher ID 与 manifest 不匹配", ErrRestoreRejected)
	}
	if err := verifyBackupEvidence(backupDB, manifest); err != nil {
		return nil, err
	}
	if err := validateBackupDatabase(ctx, backupDB, cipher, manifest); err != nil {
		return nil, err
	}

	lock, err := acquireInstanceLock(absDB)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	intentPath := restoreIntentPath(absDB)
	if existing, loadErr := loadRestoreIntent(intentPath); loadErr == nil && existing.Phase != restorePhaseComplete {
		return nil, fmt.Errorf("%w: 已有未完成 intent phase=%s，请先让 Store.Open 续做或人工处理隔离目录", ErrRestorePending, existing.Phase)
	}

	isolationDir, err := newIsolationDirectory(absDB)
	if err != nil {
		return nil, err
	}
	stagingPath := absDB + ".restore-staging"
	if err := removeIfExists(stagingPath); err != nil {
		return nil, err
	}
	if err := copyFileRestricted(backupDB, stagingPath); err != nil {
		return nil, err
	}
	if err := syncAndRestrictFile(stagingPath); err != nil {
		_ = os.Remove(stagingPath)
		return nil, err
	}
	if err := verifyBackupEvidence(stagingPath, manifest); err != nil {
		_ = os.Remove(stagingPath)
		return nil, err
	}

	intent := restoreIntent{
		FormatVersion:      restoreIntentVersion,
		Phase:              restorePhasePrepared,
		DatabasePath:       absDB,
		ManifestPath:       absManifest,
		BackupDatabasePath: backupDB,
		StagingPath:        stagingPath,
		IsolationDirectory: isolationDir,
		DatabaseSHA256:     manifest.DatabaseSHA256,
		DatabaseSize:       manifest.DatabaseSize,
		SourceSchema:       manifest.SourceSchema,
		PairedBuildID:      manifest.PairedBuildID,
		ReaderContract:     manifest.ReaderContract,
		LegacyCipherID:     manifest.LegacyCipherID,
		UpdatedAt:          time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeRestoreIntent(intentPath, intent); err != nil {
		_ = os.Remove(stagingPath)
		return nil, err
	}
	return resumeRestoreIntent(ctx, intentPath, cipher)
}

// resumeIncompleteRestoreIfAny continues a crash-interrupted restore before Open migrates.
func resumeIncompleteRestoreIfAny(ctx context.Context, databasePath string, cipher *Cipher) error {
	path := dbPathOf(databasePath)
	if path == "" || path == ":memory:" {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	intentPath := restoreIntentPath(abs)
	intent, err := loadRestoreIntent(intentPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRestorePending, err)
	}
	if intent.Phase == restorePhaseComplete {
		_ = os.Remove(intentPath)
		return nil
	}
	_, err = resumeRestoreIntent(ctx, intentPath, cipher)
	return err
}

func resumeRestoreIntent(ctx context.Context, intentPath string, cipher *Cipher) (*RestoreResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	intent, err := loadRestoreIntent(intentPath)
	if err != nil {
		return nil, err
	}
	if cipher != nil && intent.LegacyCipherID != "" && intent.LegacyCipherID != cipher.KeyID() {
		return nil, fmt.Errorf("%w: cipher ID 与 restore intent 不匹配", ErrRestoreRejected)
	}

	switch intent.Phase {
	case restorePhasePrepared:
		if err := isolateLiveDatabaseGroup(intent); err != nil {
			return nil, err
		}
		intent.Phase = restorePhaseIsolated
		intent.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := writeRestoreIntent(intentPath, intent); err != nil {
			return nil, err
		}
		fallthrough
	case restorePhaseIsolated:
		if err := installStagedDatabase(intent); err != nil {
			return nil, err
		}
		intent.Phase = restorePhaseInstalled
		intent.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := writeRestoreIntent(intentPath, intent); err != nil {
			return nil, err
		}
		fallthrough
	case restorePhaseInstalled:
		if err := finalizeInstalledDatabase(intent); err != nil {
			return nil, err
		}
		intent.Phase = restorePhaseComplete
		intent.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := writeRestoreIntent(intentPath, intent); err != nil {
			return nil, err
		}
		_ = os.Remove(intentPath)
	case restorePhaseComplete:
		_ = os.Remove(intentPath)
	default:
		return nil, fmt.Errorf("%w: 未知 restore phase %q", ErrRestorePending, intent.Phase)
	}

	return &RestoreResult{
		RestoredSchemaVersion: intent.SourceSchema,
		PairedBuildID:         intent.PairedBuildID,
		ReaderContract:        intent.ReaderContract,
		IsolationDirectory:    intent.IsolationDirectory,
		DataLossBoundary:      dataLossBoundary(intent.SourceSchema),
	}, nil
}

func dataLossBoundary(sourceSchema int) string {
	switch sourceSchema {
	case 2:
		return "restores schema-2 cutover backup; schema-3-only rows created after cutover are not present"
	case 1:
		return "restores schema-1 / pre-P0 backup; all P0 schema-2/3 configuration created after that backup is lost"
	case 0:
		return "restores legacy schema-0 variant backup; all later configuration is lost"
	default:
		return fmt.Sprintf("restores source schema %d backup; later writes are not present", sourceSchema)
	}
}

func validateBackupPaths(databasePath, manifestPath string) (absDB, absManifest, backupDB string, manifest *BackupManifest, err error) {
	if databasePath == "" || databasePath == ":memory:" || manifestPath == "" {
		return "", "", "", nil, fmt.Errorf("%w: 需要绝对数据库路径与 manifest 路径", ErrRestoreRejected)
	}
	absDB, err = filepath.Abs(databasePath)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("%w: %v", ErrRestoreRejected, err)
	}
	absManifest, err = filepath.Abs(manifestPath)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("%w: %v", ErrRestoreRejected, err)
	}
	if err := rejectSymlinkOrReparse(absDB); err != nil {
		return "", "", "", nil, err
	}
	if err := rejectSymlinkOrReparse(absManifest); err != nil {
		return "", "", "", nil, err
	}
	dbDir := filepath.Dir(absDB)
	backupRoot := filepath.Join(dbDir, "backups")
	rel, relErr := filepath.Rel(backupRoot, absManifest)
	if relErr != nil || strings.HasPrefix(rel, "..") {
		return "", "", "", nil, fmt.Errorf("%w: manifest 必须位于数据库同目录下的 backups/ 子树", ErrRestoreRejected)
	}
	raw, err := os.ReadFile(absManifest)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("读取 manifest: %w", err)
	}
	var m BackupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", "", nil, fmt.Errorf("%w: manifest JSON 无效: %v", ErrRestoreRejected, err)
	}
	if m.FormatVersion != backupManifestFormatVersion {
		return "", "", "", nil, fmt.Errorf("%w: 不支持的 manifest format_version=%d", ErrRestoreRejected, m.FormatVersion)
	}
	if m.DatabaseFile == "" || m.DatabaseSHA256 == "" || m.ReaderContract == "" || m.PairedBuildID == "" {
		return "", "", "", nil, fmt.Errorf("%w: manifest 缺少必要字段", ErrRestoreRejected)
	}
	if m.SourceSchema < 0 || m.TargetSchema != m.SourceSchema+1 {
		return "", "", "", nil, fmt.Errorf("%w: manifest schema 边界无效 source=%d target=%d", ErrRestoreRejected, m.SourceSchema, m.TargetSchema)
	}
	backupDB = filepath.Join(filepath.Dir(absManifest), filepath.Base(m.DatabaseFile))
	if err := rejectSymlinkOrReparse(backupDB); err != nil {
		return "", "", "", nil, err
	}
	relDB, relDBErr := filepath.Rel(backupRoot, backupDB)
	if relDBErr != nil || strings.HasPrefix(relDB, "..") {
		return "", "", "", nil, fmt.Errorf("%w: backup 数据库必须位于 backups/ 子树", ErrRestoreRejected)
	}
	return absDB, absManifest, backupDB, &m, nil
}

func verifyBackupEvidence(path string, manifest *BackupManifest) error {
	size, sha, err := fileEvidence(path)
	if err != nil {
		return err
	}
	if size != manifest.DatabaseSize || !strings.EqualFold(sha, manifest.DatabaseSHA256) {
		return fmt.Errorf("%w: backup 文件证据与 manifest 不符", ErrRestoreRejected)
	}
	return nil
}

func validateBackupDatabase(ctx context.Context, path string, cipher *Cipher, manifest *BackupManifest) error {
	db, err := sql.Open("sqlite", path+connPragmas)
	if err != nil {
		return fmt.Errorf("打开 backup 数据库: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("连接 backup 数据库: %w", err)
	}
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return fmt.Errorf("backup integrity_check: %w", err)
	}
	if !strings.EqualFold(integrity, "ok") {
		return fmt.Errorf("%w: integrity_check=%s", ErrRestoreRejected, integrity)
	}
	state, err := inspectSchemaState(ctx, db)
	if err != nil {
		return err
	}
	if state.Empty || state.Version != manifest.SourceSchema {
		return fmt.Errorf("%w: backup schema version=%d fingerprint=%s，manifest source=%d",
			ErrRestoreRejected, state.Version, state.Fingerprint, manifest.SourceSchema)
	}
	if manifest.SourceFingerprint != "" && state.Fingerprint != manifest.SourceFingerprint {
		return fmt.Errorf("%w: backup fingerprint 与 manifest 不符", ErrRestoreRejected)
	}
	if err := validateLegacyUpstreamKeys(ctx, db, cipher); err != nil {
		return fmt.Errorf("%w: %v", ErrRestoreRejected, err)
	}
	return nil
}

func isolateLiveDatabaseGroup(intent restoreIntent) error {
	if err := os.MkdirAll(intent.IsolationDirectory, 0o700); err != nil {
		return fmt.Errorf("创建隔离目录: %w", err)
	}
	if err := os.Chmod(intent.IsolationDirectory, 0o700); err != nil {
		return err
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := intent.DatabasePath + suffix
		if _, err := os.Lstat(src); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := rejectSymlinkOrReparse(src); err != nil {
			return err
		}
		dst := filepath.Join(intent.IsolationDirectory, filepath.Base(src))
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("隔离 %s: %w", src, err)
		}
	}
	return syncDirectory(filepath.Dir(intent.DatabasePath))
}

func installStagedDatabase(intent restoreIntent) error {
	if _, err := os.Lstat(intent.StagingPath); err != nil {
		return fmt.Errorf("staging 库缺失: %w", err)
	}
	if err := os.Rename(intent.StagingPath, intent.DatabasePath); err != nil {
		return fmt.Errorf("安装恢复库: %w", err)
	}
	return syncDirectory(filepath.Dir(intent.DatabasePath))
}

func finalizeInstalledDatabase(intent restoreIntent) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		sidecar := intent.DatabasePath + suffix
		if _, err := os.Lstat(sidecar); err == nil {
			return fmt.Errorf("%w: 正式路径仍残留 sidecar %s", ErrRestorePending, sidecar)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	size, sha, err := fileEvidence(intent.DatabasePath)
	if err != nil {
		return err
	}
	if size != intent.DatabaseSize || !strings.EqualFold(sha, intent.DatabaseSHA256) {
		return fmt.Errorf("%w: 安装后文件证据不符", ErrRestoreRejected)
	}
	if err := os.Chmod(intent.DatabasePath, 0o600); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(intent.DatabasePath))
}

func restoreIntentPath(absDB string) string {
	return filepath.Join(filepath.Dir(absDB), restoreIntentFileName)
}

func loadRestoreIntent(path string) (restoreIntent, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return restoreIntent{}, err
	}
	var intent restoreIntent
	if err := json.Unmarshal(raw, &intent); err != nil {
		return restoreIntent{}, fmt.Errorf("解析 restore intent: %w", err)
	}
	if intent.FormatVersion != restoreIntentVersion {
		return restoreIntent{}, fmt.Errorf("不支持的 restore intent version=%d", intent.FormatVersion)
	}
	return intent, nil
}

func writeRestoreIntent(path string, intent restoreIntent) error {
	raw, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := writeSyncedFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("写 restore intent: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func newIsolationDirectory(absDB string) (string, error) {
	suffix, err := backupRandomSuffix()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(filepath.Dir(absDB), fmt.Sprintf("isolated-%s-%s",
		time.Now().UTC().Format("20060102T150405Z"), suffix))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func rejectSymlinkOrReparse(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// Database path may not exist yet when restoring onto a missing live file.
		parent := filepath.Dir(path)
		parentInfo, parentErr := os.Lstat(parent)
		if parentErr != nil {
			return fmt.Errorf("%w: %v", ErrRestoreRejected, parentErr)
		}
		if parentInfo.Mode()&os.ModeSymlink != 0 || pathInfoIsReparsePoint(parentInfo) {
			return fmt.Errorf("%w: 目录含 symlink/reparse point", ErrRestoreRejected)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || pathInfoIsReparsePoint(info) {
		return fmt.Errorf("%w: %s 是 symlink/reparse point", ErrRestoreRejected, path)
	}
	return nil
}

func copyFileRestricted(src, dst string) error {
	content, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeSyncedFile(dst, content, 0o600)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
