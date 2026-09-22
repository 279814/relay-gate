// Package config 处理基础设施级配置（环境变量）。
// 业务配置在数据库里，可热改；这里的只在启动时读一次。
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/keyring"
)

type Config struct {
	Addr    string // 监听地址
	DBPath  string
	EncKey  string // ENCRYPTION_KEY，用于加密上游 api_key
	AdminPW string // 管理界面登录口令（环境变量；可与 Argon2id 哈希并存）

	// RelayKeys 是本服务发放给客户端的 key（可多个，逗号分隔）。
	// 必须非空——空表示任何人都能白用你所有上游 key。
	RelayKeys []string
}

func Load() (*Config, error) {
	c := &Config{
		Addr:    env("RELAY_ADDR", "127.0.0.1:18787"),
		DBPath:  env("RELAY_DB", "data/relay-gate.db"),
		EncKey:  strings.TrimSpace(os.Getenv("ENCRYPTION_KEY")),
		AdminPW: os.Getenv("ADMIN_PASSWORD"),
	}
	for _, k := range strings.Split(os.Getenv("RELAY_KEYS"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			c.RelayKeys = append(c.RelayKeys, k)
		}
	}
	if err := c.fillFromSecretsArtifacts(); err != nil {
		return nil, err
	}
	return c, c.validate()
}

// DataDir returns the directory that holds the SQLite file and secrets/.
func (c *Config) DataDir() string {
	dir := filepath.Dir(c.DBPath)
	if dir == "." || dir == "" {
		return "data"
	}
	return dir
}

// fillFromSecretsArtifacts loads ENCRYPTION_KEY / RELAY_KEYS from
// data/secrets/ when the corresponding environment variable is absent.
//
// Precedence: a non-empty environment variable always wins over on-disk
// bootstrap/migrate artifacts. Existing env-only deployments are unchanged.
// Secret bytes are never included in returned errors.
func (c *Config) fillFromSecretsArtifacts() error {
	dataDir := c.DataDir()
	if c.EncKey == "" {
		_, master, err := keyring.Open(dataDir).LoadActive()
		switch {
		case err == nil && strings.TrimSpace(master) != "":
			c.EncKey = master
		case err == nil:
			// empty active: leave unset; validate reports missing
		case errors.Is(err, keyring.ErrNotInitialized):
			// no keyring yet: leave unset
		default:
			return fmt.Errorf("读取 keyring 失败（未回显密钥）: %w", err)
		}
	}
	if len(c.RelayKeys) == 0 {
		doc, err := credential.LoadPersistedFile(dataDir)
		switch {
		case err == nil && strings.TrimSpace(doc.RelayKey) != "":
			c.RelayKeys = []string{strings.TrimSpace(doc.RelayKey)}
		case err == nil:
			// empty relay: leave unset
		case errors.Is(err, os.ErrNotExist):
			// no credentials file: leave unset
		default:
			return fmt.Errorf("读取 bootstrap-credentials 失败（未回显密钥）: %w", err)
		}
	}
	return nil
}

// validate 对三项凭据强制要求。
//
// 刻意选择「缺失即拒绝启动」而不是「自动生成并打印」：自动生成的值在容器重启后
// 会变（除非再落库，又绕回同一个问题），而 ENCRYPTION_KEY 变了等于所有上游 key
// 全部无法解密。宁可启动失败并说清怎么办。
//
// ADMIN_PASSWORD 可被 data/secrets/ 下的 Argon2id 哈希替代（bootstrap/migrate/reset-admin）；
// ENCRYPTION_KEY / RELAY_KEYS 可在环境变量缺省时分别从 keyring.json /
// bootstrap-credentials.json 加载（环境变量优先）。环境变量明文仍受支持（旧部署与测试）。
func (c *Config) validate() error {
	var missing []string
	if len(c.EncKey) < 16 {
		missing = append(missing, "ENCRYPTION_KEY（至少 16 字符，用于加密上游 api_key；"+
			"**丢失后已存的 key 无法恢复**，请妥善备份；"+
			"可设环境变量，或完成 credentials bootstrap/migrate 写入 data/secrets/keyring.json）")
	}
	if len(c.RelayKeys) == 0 {
		missing = append(missing, "RELAY_KEYS（本服务发放给客户端的 key，逗号分隔多个；"+
			"留空等于把你所有上游 key 免费公开；"+
			"可设环境变量，或完成 credentials bootstrap/migrate 写入 bootstrap-credentials.json）")
	}
	hashOK := credential.HasAdminHash(c.DataDir())
	if len(c.AdminPW) < 8 && !hashOK {
		missing = append(missing, "ADMIN_PASSWORD（管理界面登录口令，至少 8 字符；"+
			"或先完成 credentials bootstrap/migrate 写入 Argon2id 哈希）")
	}
	if len(missing) > 0 {
		return fmt.Errorf("缺少必需的凭据：\n  - %s\n\n"+
			"新安装请先运行一次性：relay-gate credentials bootstrap --data-dir <data>\n"+
			"旧部署迁移：relay-gate credentials migrate --data-dir <data> --db <db>\n"+
			"或设置环境变量（兼容旧部署；与文件同时存在时环境变量优先）。生成随机值：openssl rand -hex 32",
			strings.Join(missing, "\n  - "))
	}
	return nil
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
