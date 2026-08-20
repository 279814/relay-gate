package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"modernc.org/sqlite"
)

const backupManifestFormatVersion = 1

type MigrationBackupSpec struct {
	SourceSchema      int
	SourceVariant     string
	SourceFingerprint string
	TargetSchema      int
	LegacyCipherID    string
	SourceValidator   string
	PairedBuildID     string
	ReaderContract    string
	CreatedAt         time.Time
}

type MigrationBackupIdentity struct {
	PairedBuildID  string
	ReaderContract string
	CreatedAt      time.Time
}

type MigrationBackupResult struct {
	Directory    string
	DatabasePath string
	ManifestPath string
	Manifest     BackupManifest
}

type sqliteBackupSource interface {
	NewBackup(string) (*sqlite.Backup, error)
}

func createMigrationBackup(ctx context.Context, conn *sql.Conn, databasePath string, spec MigrationBackupSpec) (result MigrationBackupResult, err error) {
	if conn == nil {
		return result, fmt.Errorf("migration backup: nil source connection")
	}
	if databasePath == "" || databasePath == ":memory:" {
		return result, fmt.Errorf("migration backup requires a file database")
	}
	if spec.TargetSchema != spec.SourceSchema+1 || spec.SourceFingerprint == "" || spec.LegacyCipherID == "" {
		return result, fmt.Errorf("migration backup metadata is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	createdAt := spec.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	randomSuffix, err := backupRandomSuffix()
	if err != nil {
		return result, err
	}
	backupRoot := filepath.Join(filepath.Dir(databasePath), "backups")
	if err := os.MkdirAll(backupRoot, 0o700); err != nil {
		return result, fmt.Errorf("创建备份根目录: %w", err)
	}
	if err := os.Chmod(backupRoot, 0o700); err != nil {
		return result, fmt.Errorf("收紧备份根目录权限: %w", err)
	}
	baseName := fmt.Sprintf("schema-%d-to-%d-%s-%s", spec.SourceSchema, spec.TargetSchema, createdAt.Format("20060102T150405Z"), randomSuffix)
	temporaryDirectory := filepath.Join(backupRoot, "."+baseName+".tmp")
	finalDirectory := filepath.Join(backupRoot, baseName)
	if err := os.Mkdir(temporaryDirectory, 0o700); err != nil {
		return result, fmt.Errorf("创建临时备份目录: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(temporaryDirectory)
		}
	}()

	temporaryDatabase := filepath.Join(temporaryDirectory, "database.sqlite")
	if err = backupSQLiteConnection(ctx, conn, temporaryDatabase); err != nil {
		return result, err
	}
	if err = syncAndRestrictFile(temporaryDatabase); err != nil {
		return result, err
	}
	databaseSize, databaseSHA, err := fileEvidence(temporaryDatabase)
	if err != nil {
		return result, err
	}

	manifest := BackupManifest{
		FormatVersion:     backupManifestFormatVersion,
		SourceSchema:      spec.SourceSchema,
		SourceVariant:     spec.SourceVariant,
		SourceFingerprint: spec.SourceFingerprint,
		TargetSchema:      spec.TargetSchema,
		DatabaseFile:      filepath.Base(temporaryDatabase),
		DatabaseSize:      databaseSize,
		DatabaseSHA256:    databaseSHA,
		LegacyCipherID:    spec.LegacyCipherID,
		SourceValidator:   spec.SourceValidator,
		PairedBuildID:     spec.PairedBuildID,
		ReaderContract:    spec.ReaderContract,
		CreatedAt:         createdAt.Format(time.RFC3339Nano),
	}
	temporaryManifest := filepath.Join(temporaryDirectory, "manifest.json.tmp")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return result, fmt.Errorf("编码备份 manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err = writeSyncedFile(temporaryManifest, manifestBytes, 0o600); err != nil {
		return result, fmt.Errorf("写备份 manifest: %w", err)
	}
	manifestPath := filepath.Join(temporaryDirectory, "manifest.json")
	if err = os.Rename(temporaryManifest, manifestPath); err != nil {
		return result, fmt.Errorf("发布备份 manifest: %w", err)
	}
	if err = syncDirectory(temporaryDirectory); err != nil {
		return result, fmt.Errorf("同步临时备份目录: %w", err)
	}
	if err = os.Rename(temporaryDirectory, finalDirectory); err != nil {
		return result, fmt.Errorf("发布备份目录: %w", err)
	}
	if err = syncDirectory(backupRoot); err != nil {
		return result, fmt.Errorf("同步备份根目录: %w", err)
	}

	result = MigrationBackupResult{
		Directory:    finalDirectory,
		DatabasePath: filepath.Join(finalDirectory, filepath.Base(temporaryDatabase)),
		ManifestPath: filepath.Join(finalDirectory, filepath.Base(manifestPath)),
		Manifest:     manifest,
	}
	return result, nil
}

func backupSQLiteConnection(ctx context.Context, conn *sql.Conn, destination string) error {
	return conn.Raw(func(driverConnection any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		source, ok := driverConnection.(sqliteBackupSource)
		if !ok {
			return fmt.Errorf("SQLite driver does not support online backup")
		}
		backup, err := source.NewBackup(destination)
		if err != nil {
			return fmt.Errorf("创建 SQLite backup handle: %w", err)
		}
		more, stepErr := backup.Step(-1)
		if stepErr != nil {
			_ = backup.Finish()
			return fmt.Errorf("复制 SQLite backup: %w", stepErr)
		}
		if more {
			_ = backup.Finish()
			return fmt.Errorf("复制 SQLite backup: full step unexpectedly incomplete")
		}
		destinationConnection, commitErr := backup.Commit()
		if destinationConnection != nil {
			_ = destinationConnection.Close()
		}
		if commitErr != nil {
			return fmt.Errorf("完成 SQLite backup: %w", commitErr)
		}
		return nil
	})
}

func backupRandomSuffix() (string, error) {
	var value [6]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("生成备份目录随机后缀: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func syncAndRestrictFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("打开备份数据库: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("同步备份数据库: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("关闭备份数据库: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("收紧备份数据库权限: %w", err)
	}
	return nil
}

func writeSyncedFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func fileEvidence(path string) (int64, string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, "", fmt.Errorf("读取备份数据库: %w", err)
	}
	sum := sha256.Sum256(content)
	return int64(len(content)), hex.EncodeToString(sum[:]), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}
