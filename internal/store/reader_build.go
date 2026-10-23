package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
)

// CurrentReaderBuildID identifies the executable artifact, not a claimed Git
// release. Version/VCS/platform are diagnostic labels; the SHA-256 identifies
// the exact binary an operator must retain. Compute once during server startup.
func CurrentReaderBuildID(version string) (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("定位配对 reader 程序: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("读取配对 reader 程序: %w", err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("校验配对 reader 程序: %w", err)
	}
	version = strings.TrimSpace(version)
	if version == "" {
		version = "dev"
	}
	revision, modified := "unknown", "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value
			}
		}
	}
	return fmt.Sprintf("sha256:%s version=%s vcs=%s modified=%s go=%s platform=%s/%s", hex.EncodeToString(digest.Sum(nil)),
		url.QueryEscape(version), url.QueryEscape(revision), url.QueryEscape(modified), url.QueryEscape(runtime.Version()), runtime.GOOS, runtime.GOARCH), nil
}

// OpenLockedWithReaderBuildID records startup's actual artifact identity for
// rotation and schema-9 through schema-11 migration backups. Earlier backups retain
// historical reader pins; identity never changes restore authorization.
func OpenLockedWithReaderBuildID(dsn string, c *Cipher, held *InstanceLock, buildID string) (*Store, error) {
	if strings.TrimSpace(buildID) == "" {
		return nil, fmt.Errorf("配对 reader build identity 不能为空")
	}
	return openWithHeldLock(dsn, c, held, buildID)
}
