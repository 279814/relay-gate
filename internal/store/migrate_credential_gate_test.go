package store

import (
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// 迁移产出的模板必须过得了凭据门禁，否则升级会中断。
//
// 这条钉的是一处跨文件的耦合，两边单独看都不显然：
//
// probetemplate 的凭据门禁（§4.5）会拒绝含字面凭据的模板，而
// migrate_backfill.go:375 在「扫描失败且这条记录**没有**被隔离」时
// 直接返回 error —— 那个 error 会让整次 schema 1→2 升级失败。
// 也就是说，凭据门禁一旦比迁移的脱敏逻辑更严，用户就升不上来了，
// 而症状是「升级报错」，不会有人想到去看模板扫描器。
//
// 现在两者是对齐的，靠的是迁移侧先做了三件事：
//   - 认证头一律不产出为模板（legacyHeaderTemplates 里 IsAuthHeader 那支
//     只判要不要隔离，从不把值写进 values）
//   - 上游自己的 key 被替换成 {{UPSTREAM_API_KEY}}
//   - 其余可疑值换成 fingerprint 并置 quarantined
//
// 任何一侧改动都可能打破这个对齐 —— 这条测试就是那时的报警。
func TestMigrationOutputPassesCredentialGate(t *testing.T) {
	cases := []struct {
		name    string
		apiKey  string
		headers map[string]string
	}{
		{"上游 key 出现在自定义头", "sk-ant-api03-REALKEYVALUE1234",
			map[string]string{"X-Tenant": "sk-ant-api03-REALKEYVALUE1234"}},
		// 上游 key 只是更长串的前缀：ReplaceAll 之后仍会剩下尾巴，
		// 而那截尾巴不该让门禁把整条记录判成凭据。
		{"上游 key 是更长串的前缀", "sk-ant-api03-REALKEY",
			map[string]string{"X-Tenant": "sk-ant-api03-REALKEY-plus-trailing-stuff"}},
		// 别的厂商的 key：迁移侧认不出它是「这个站的 key」，只能靠
		// legacyValueLooksSecret 的启发式判断并隔离。
		{"别的厂商 key", "sk-ant-mykey-1234567890",
			map[string]string{"X-Other": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
		// 认证头带字面值：迁移侧刻意不把它产出为模板，所以门禁看不到它。
		{"认证头带字面值", "sk-ant-real-key-1234567890",
			map[string]string{"Authorization": "Bearer sk-ant-someone-elses-key-999"}},
	}

	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			upstream := &legacyUpstreamConfig{
				apiKey:       testCase.apiKey,
				probeHeaders: testCase.headers,
			}
			headers, quarantined := legacyHeaderTemplates(cipher, upstream, model.ProtoAnthropic, false)

			_, scanErr := probetemplate.ScanRequiredSecrets(model.EndpointMessages,
				probetemplate.TemplateContent{Method: "POST", Headers: headers, Body: []byte(`{}`)})

			// 非隔离却过不了门禁 = 升级中断（migrate_backfill.go:375）。
			if scanErr != nil && !quarantined {
				t.Errorf("这条记录没被隔离却过不了凭据门禁，会让 schema 1→2 升级整体失败: %v", scanErr)
			}
			// 顺带确认迁移本身没把明文 key 留在模板里。
			for _, header := range headers {
				for _, value := range header.Values {
					if testCase.apiKey != "" && strings.Contains(value, testCase.apiKey) {
						t.Errorf("头 %q 残留明文 key: %q", header.Name, value)
					}
				}
			}
		})
	}
}

// 认证头的值绝不进迁移产出的模板。
//
// 单独一条是因为它是上一条测试能成立的前提：迁移侧若哪天改成「把认证头
// 也产出为模板」，凭据门禁会立刻拒绝它，于是升级中断 —— 而那时上一条
// 测试报的是「升级会中断」，这条报的才是「为什么」。
func TestMigrationNeverEmitsAuthHeaderTemplates(t *testing.T) {
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &legacyUpstreamConfig{
		apiKey: "sk-ant-real-key-1234567890",
		probeHeaders: map[string]string{
			"Authorization": "Bearer sk-ant-real-key-1234567890",
			"X-Api-Key":     "sk-ant-real-key-1234567890",
			"Api-Key":       "sk-ant-real-key-1234567890",
		},
	}

	headers, _ := legacyHeaderTemplates(cipher, upstream, model.ProtoAnthropic, false)
	for _, header := range headers {
		if model.IsAuthHeader(header.Name) {
			t.Errorf("迁移不该把认证头 %q 产出为模板：认证由 Endpoint 的 auth profile "+
				"决定（§7.2），模板里出现它就是第二个 key 来源，值 = %q", header.Name, header.Values)
		}
	}
}
