// Package config 处理基础设施级配置（环境变量）。
// 业务配置在数据库里，可热改；这里的只在启动时读一次。
package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Addr    string // 监听地址
	DBPath  string
	EncKey  string // ENCRYPTION_KEY，用于加密上游 api_key
	AdminPW string // 管理界面登录口令

	// RelayKeys 是本服务发放给客户端的 key（可多个，逗号分隔）。
	// 必须非空——空表示任何人都能白用你所有上游 key。
	RelayKeys []string
}

func Load() (*Config, error) {
	c := &Config{
		Addr:    env("RELAY_ADDR", "127.0.0.1:18787"),
		DBPath:  env("RELAY_DB", "data/relay-gate.db"),
		EncKey:  os.Getenv("ENCRYPTION_KEY"),
		AdminPW: os.Getenv("ADMIN_PASSWORD"),
	}
	for _, k := range strings.Split(os.Getenv("RELAY_KEYS"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			c.RelayKeys = append(c.RelayKeys, k)
		}
	}
	return c, c.validate()
}

// validate 对三项凭据强制要求。
//
// 刻意选择「缺失即拒绝启动」而不是「自动生成并打印」：自动生成的值在容器重启后
// 会变（除非再落库，又绕回同一个问题），而 ENCRYPTION_KEY 变了等于所有上游 key
// 全部无法解密。宁可启动失败并说清怎么办。
func (c *Config) validate() error {
	var missing []string
	if len(c.EncKey) < 16 {
		missing = append(missing, "ENCRYPTION_KEY（至少 16 字符，用于加密上游 api_key；"+
			"**丢失后已存的 key 无法恢复**，请妥善备份）")
	}
	if len(c.RelayKeys) == 0 {
		missing = append(missing, "RELAY_KEYS（本服务发放给客户端的 key，逗号分隔多个；"+
			"留空等于把你所有上游 key 免费公开）")
	}
	if len(c.AdminPW) < 8 {
		missing = append(missing, "ADMIN_PASSWORD（管理界面登录口令，至少 8 字符）")
	}
	if len(missing) > 0 {
		return fmt.Errorf("缺少必需的环境变量：\n  - %s\n\n"+
			"生成随机值：openssl rand -hex 32", strings.Join(missing, "\n  - "))
	}
	return nil
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
