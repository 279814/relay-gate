package outbound

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// FuzzResolve 喂任意 base_url / override / query / Secret 组合。
//
// 两条不变量：不 panic，且**绝不产生跨 origin 的 target**。后者是安全边界 ——
// 一个能被 query 或 override 撬到别的 host 的 Resolver，等于让站级
// Reachability 结论代表另一个网络目标（§7.1）。
func FuzzResolve(f *testing.F) {
	f.Add("https://a.example", "", "", "")
	f.Add("https://a.example/api/", "https://a.example/x", "beta=true", "sk-1")
	f.Add("https://a.example:8443", "https://a.example:8443/y", "a=%2f&b=+", "a&b=c#d")
	f.Add("https://a.example", "https://evil.example/z", "", "")
	f.Add("https://a.example", "//evil.example/z", "@evil.example", "\r\n")
	f.Add("http://a.example", "http://a.example/../..//x", "?=&&==", "\x00")

	f.Fuzz(func(t *testing.T, base, override, incoming, secret string) {
		up := &model.ProbeUpstreamConfig{ID: 10, BaseURL: base, CredentialRevision: 1}
		endpoint := &model.UpstreamEndpoint{
			ID: 1, UpstreamID: 10, Kind: model.EndpointMessages,
			URLMode:     model.EndpointURLCanonical,
			URLOverride: override,
			AuthProfile: model.EndpointAuthProfile{
				Mode: model.AuthModeXAPIKey, SecretRef: "upstream_api_key", Revision: 1,
			},
			Revision: 1,
		}
		if secret != "" {
			endpoint.FixedQueryTemplate = "key={{UPSTREAM_API_KEY}}"
		}

		got, err := NewResolver(fakeHasher{keyID: "fz"}).Resolve(context.Background(), ResolveInput{
			Upstream: up, Endpoint: endpoint, IncomingRawQuery: incoming,
			Values: staticValues{"UPSTREAM_API_KEY": {Plain: []byte(secret), Revision: 1}},
			Use:    ResolveRealForward,
		})
		if err != nil {
			return // 拒绝是合法结果；这里只关心「接受了什么」
		}

		// 成功的结果必须与 base_url 同源。用重新解析后的 URL 比较，
		// 因为真正发出去的是 RawURL 那个字符串。
		baseParsed, parseErr := url.Parse(base)
		if parseErr != nil {
			t.Fatalf("接受了一个解析不了的 base_url %q", base)
		}
		reparsed, parseErr := url.Parse(got.RawURL)
		if parseErr != nil {
			t.Fatalf("产出了解析不了的 URL %q", got.RawURL)
		}
		if !strings.EqualFold(reparsed.Scheme, baseParsed.Scheme) {
			t.Fatalf("scheme 漂移: base %q -> %q", base, got.RawURL)
		}
		if !strings.EqualFold(reparsed.Hostname(), baseParsed.Hostname()) {
			t.Fatalf("跨 origin: base %q -> %q", base, got.RawURL)
		}
		if effectivePort(reparsed) != effectivePort(baseParsed) {
			t.Fatalf("端口漂移: base %q -> %q", base, got.RawURL)
		}
		if reparsed.User != nil {
			t.Fatalf("产出了带 userinfo 的 URL %q", got.RawURL)
		}
		if reparsed.Fragment != "" || strings.Contains(got.RawURL, "#") {
			t.Fatalf("产出了带 fragment 的 URL %q", got.RawURL)
		}
		for _, character := range []byte(got.RawURL) {
			if character < 0x20 || character == 0x7f || character == ' ' {
				t.Fatalf("产出了含控制字符/空格的 URL %q", got.RawURL)
			}
		}
	})
}
