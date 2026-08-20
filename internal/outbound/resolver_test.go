package outbound

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// fakeHasher 是一个可换 key 的假 digest，用于验证 RequestURLHash
// 「同 key 稳定、换 key 变化、携带 key ID」这三条，而不依赖 store.Cipher。
type fakeHasher struct{ keyID string }

func (hasher fakeHasher) SumRequestURL(raw []byte) string {
	// 刻意不是 SHA-256：真实实现是 keyed HMAC，测试替身只要保证
	// 「随 key 与输入变化」即可。
	var accumulator uint64 = 1469598103934665603
	for _, character := range append([]byte(hasher.keyID+"\x00"), raw...) {
		accumulator ^= uint64(character)
		accumulator *= 1099511628211
	}
	return hasher.keyID + ":" + strings.ToLower(strings.TrimSpace(
		string([]byte{byte('a' + accumulator%26), byte('a' + (accumulator>>8)%26),
			byte('a' + (accumulator>>16)%26), byte('a' + (accumulator>>24)%26)})))
}

type staticValues map[string]ResolvedValue

func (values staticValues) ResolveValue(_ context.Context, name string) (ResolvedValue, error) {
	value, ok := values[name]
	if !ok {
		return ResolvedValue{}, errors.New("no such value: " + name)
	}
	return value, nil
}

type fakeLegacy struct {
	plain    string
	revision int64
	id       int64
	err      error
	calls    int
}

func (legacy *fakeLegacy) ResolveLegacyURL(_ context.Context, id, expectedRevision int64) ([]byte, error) {
	legacy.calls++
	if legacy.err != nil {
		return nil, legacy.err
	}
	if id != legacy.id || expectedRevision != legacy.revision {
		return nil, errors.New("revision mismatch")
	}
	return []byte(legacy.plain), nil
}

func testUpstream() *model.ProbeUpstreamConfig {
	return &model.ProbeUpstreamConfig{ID: 10, BaseURL: "https://a.example", CredentialRevision: 3}
}

func canonicalEndpoint(kind model.EndpointKind) *model.UpstreamEndpoint {
	return &model.UpstreamEndpoint{
		ID: 1, UpstreamID: 10, Kind: kind,
		URLMode:     model.EndpointURLCanonical,
		AuthProfile: model.EndpointAuthProfile{Mode: model.AuthModeXAPIKey, SecretRef: "upstream_api_key", Revision: 1},
		Revision:    4,
	}
}

func newTestResolver() *Resolver { return NewResolver(fakeHasher{keyID: "k1"}) }

func resolve(t *testing.T, in ResolveInput) ResolvedTarget {
	t.Helper()
	if in.Use == "" {
		in.Use = ResolveRealForward
	}
	got, err := newTestResolver().Resolve(context.Background(), in)
	if err != nil {
		t.Fatalf("Resolve 应成功，得到错误 %v", err)
	}
	return got
}

func resolveErr(t *testing.T, in ResolveInput) error {
	t.Helper()
	if in.Use == "" {
		in.Use = ResolveRealForward
	}
	got, err := newTestResolver().Resolve(context.Background(), in)
	if err == nil {
		t.Fatalf("Resolve 应失败，却得到 %q", got.RawURL)
	}
	return err
}

// ── 测试 1：五个 Endpoint 的 canonical path ───────────────────

func TestResolve_CanonicalPaths(t *testing.T) {
	cases := []struct {
		kind model.EndpointKind
		want string
	}{
		{model.EndpointMessages, "https://a.example/v1/messages"},
		{model.EndpointResponses, "https://a.example/v1/responses"},
		{model.EndpointChatCompletions, "https://a.example/v1/chat/completions"},
		{model.EndpointCountTokens, "https://a.example/v1/messages/count_tokens"},
		{model.EndpointModels, "https://a.example/v1/models"},
	}
	for _, c := range cases {
		t.Run(string(c.kind), func(t *testing.T) {
			got := resolve(t, ResolveInput{Upstream: testUpstream(), Endpoint: canonicalEndpoint(c.kind)})
			if got.RawURL != c.want {
				t.Errorf("want %q got %q", c.want, got.RawURL)
			}
			if got.EndpointRevision != 4 {
				t.Errorf("EndpointRevision 应透传，得到 %d", got.EndpointRevision)
			}
			if got.OriginKey != "https://a.example" {
				t.Errorf("OriginKey 应为 scheme://authority，得到 %q", got.OriginKey)
			}
		})
	}
}

// ── 测试 2：base URL 带公共路径前缀时只去尾斜杠 ────────────────

// 这条钉的是「不能用 ResolveReference」：那个函数会把 /api 整段吞掉，
// 于是请求打到 /v1/messages 而不是 /api/v1/messages —— 表现为 404，
// 而配置看起来完全正确。
func TestResolve_PreservesBasePathPrefix(t *testing.T) {
	cases := []struct {
		name string
		base string
		want string
	}{
		{"带前缀", "https://a.example/api", "https://a.example/api/v1/messages"},
		{"前缀带尾斜杠", "https://a.example/api/", "https://a.example/api/v1/messages"},
		{"多段前缀", "https://a.example/x/y", "https://a.example/x/y/v1/messages"},
		{"仅尾斜杠", "https://a.example/", "https://a.example/v1/messages"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			up := testUpstream()
			up.BaseURL = c.base
			got := resolve(t, ResolveInput{Upstream: up, Endpoint: canonicalEndpoint(model.EndpointMessages)})
			if got.RawURL != c.want {
				t.Errorf("want %q got %q", c.want, got.RawURL)
			}
		})
	}
}

// ── 测试 3：override 必须同源 ─────────────────────────────────

func TestResolve_OverrideSameOrigin(t *testing.T) {
	endpoint := canonicalEndpoint(model.EndpointMessages)
	endpoint.URLOverride = "https://a.example/custom/chat"
	got := resolve(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint})
	if got.RawURL != "https://a.example/custom/chat" {
		t.Fatalf("同源 override 应直接使用，得到 %q", got.RawURL)
	}

	// 显式端口与默认端口等价，不该被判成跨 origin。结果沿用 base_url 的
	// authority —— override 只贡献 path（§7.1），否则同一个站的两个 Endpoint
	// 会因为 authority 写法不同而落进两个连接池。
	endpoint.URLOverride = "https://a.example:443/custom/chat"
	if got := resolve(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint}); got.RawURL != "https://a.example/custom/chat" {
		t.Errorf("默认端口应与显式 443 同源且沿用 base authority，得到 %q", got.RawURL)
	}
}

func TestResolve_RejectsCrossOriginOverride(t *testing.T) {
	cases := []struct {
		name     string
		override string
	}{
		{"scheme 不同", "http://a.example/v1/messages"},
		{"host 不同", "https://b.example/v1/messages"},
		{"端口不同", "https://a.example:8443/v1/messages"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			endpoint := canonicalEndpoint(model.EndpointMessages)
			endpoint.URLOverride = c.override
			err := resolveErr(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint})
			if !strings.Contains(err.Error(), "跨 origin") {
				t.Errorf("错误应说明跨 origin，得到 %v", err)
			}
		})
	}
}

// ── 测试 4：fragment、userinfo、非 HTTP(S)、空 host 一律失败 ────

func TestResolve_RejectsUnsafeURLForms(t *testing.T) {
	cases := []struct {
		name string
		base string
	}{
		{"fragment", "https://a.example/#x"},
		{"userinfo", "https://key@a.example"},
		{"非 http(s)", "ftp://a.example"},
		{"空 host", "https:///v1"},
		{"首尾空白", " https://a.example"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			up := testUpstream()
			up.BaseURL = c.base
			resolveErr(t, ResolveInput{Upstream: up, Endpoint: canonicalEndpoint(model.EndpointMessages)})
		})
	}

	// override 侧走同一套校验
	for _, c := range cases {
		t.Run("override/"+c.name, func(t *testing.T) {
			endpoint := canonicalEndpoint(model.EndpointMessages)
			endpoint.URLOverride = c.base
			resolveErr(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint})
		})
	}
}

// ── 测试 5：query 保真 ───────────────────────────────────────

// 断言用**原字符串**比较，不比较解析后的 url.Values（验收硬要求）：
// url.Values 是 map，比较它会静默放过顺序、重复键与 `+` 的差异，
// 而那三样恰好是上游行为的差异来源。
func TestResolve_QueryFidelity(t *testing.T) {
	cases := []struct {
		name     string
		fixed    string
		incoming string
		want     string
	}{
		{"只有固定", "beta=true", "", "beta=true"},
		{"只有入站", "", "beta=true", "beta=true"},
		{"固定在前入站在后", "key=a", "beta=true", "key=a&beta=true"},
		{"同名键都保留", "beta=1", "beta=2", "beta=1&beta=2"},
		{"空值原样", "flag=", "x=", "flag=&x="},
		{"裸参数无等号", "raw", "bare", "raw&bare"},
		{"百分号大小写原样", "a=%2f%2F", "b=%3d", "a=%2f%2F&b=%3d"},
		{"加号原样不转空格", "q=a+b", "r=c+d", "q=a+b&r=c+d"},
		{"顺序不排序", "z=1&a=2", "m=3&b=4", "z=1&a=2&m=3&b=4"},
		{"两者皆空", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			endpoint := canonicalEndpoint(model.EndpointMessages)
			endpoint.FixedQueryTemplate = c.fixed
			got := resolve(t, ResolveInput{
				Upstream: testUpstream(), Endpoint: endpoint, IncomingRawQuery: c.incoming,
			})
			if got.URL.RawQuery != c.want {
				t.Errorf("RawQuery want %q got %q", c.want, got.URL.RawQuery)
			}
			wantURL := "https://a.example/v1/messages"
			if c.want != "" {
				wantURL += "?" + c.want
			}
			if got.RawURL != wantURL {
				t.Errorf("RawURL want %q got %q", wantURL, got.RawURL)
			}
		})
	}
}

// url_override 带 query 时必须失败：持久化只允许一个固定 query 来源。
func TestResolve_RejectsQueryInOverride(t *testing.T) {
	endpoint := canonicalEndpoint(model.EndpointMessages)
	endpoint.URLOverride = "https://a.example/custom?key=v"
	err := resolveErr(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint})
	if !strings.Contains(err.Error(), "fixed_query_template") {
		t.Errorf("错误应指向唯一固定 query 来源，得到 %v", err)
	}

	endpoint.FixedQueryTemplate = "key=v"
	resolveErr(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint})
}

// ── 测试 6：占位符必须占据完整 value，Secret 逐 byte 转义 ──────

func TestResolve_QueryPlaceholderMustBeWholeValue(t *testing.T) {
	cases := []string{
		"key=prefix{{UPSTREAM_API_KEY}}",
		"key={{UPSTREAM_API_KEY}}suffix",
		"{{UPSTREAM_API_KEY}}=v",
		"{{UPSTREAM_API_KEY}}",
	}
	for _, template := range cases {
		t.Run(template, func(t *testing.T) {
			endpoint := canonicalEndpoint(model.EndpointMessages)
			endpoint.FixedQueryTemplate = template
			resolveErr(t, ResolveInput{
				Upstream: testUpstream(), Endpoint: endpoint,
				Values: staticValues{"UPSTREAM_API_KEY": {Plain: []byte("sk-x"), Revision: 3}},
			})
		})
	}
}

// Secret 里的 & = # % 不能改变 query 结构 —— 否则一个含 & 的 key 会
// 凭空多出一个参数，而上游看到的是一个被截断的 key（症状：一直 401）。
func TestResolve_SecretPercentEncodedByteWise(t *testing.T) {
	endpoint := canonicalEndpoint(model.EndpointMessages)
	endpoint.FixedQueryTemplate = "key={{UPSTREAM_API_KEY}}&next=1"

	// 含结构字符与非 UTF-8 字节
	secret := []byte{'a', '&', 'b', '=', 'c', '#', 'd', '%', 0xff, 0x80, ' '}
	got := resolve(t, ResolveInput{
		Upstream: testUpstream(), Endpoint: endpoint,
		Values: staticValues{"UPSTREAM_API_KEY": {Plain: secret, Revision: 3}},
	})

	const wantQuery = "key=a%26b%3Dc%23d%25%FF%80%20&next=1"
	if got.URL.RawQuery != wantQuery {
		t.Fatalf("Secret 应逐 byte percent-encode\nwant %q\ngot  %q", wantQuery, got.URL.RawQuery)
	}
	// 参数数量与名称不变
	parsed, err := url.ParseQuery(got.URL.RawQuery)
	if err != nil {
		t.Fatalf("渲染结果应是合法 query: %v", err)
	}
	if len(parsed) != 2 || parsed.Get("key") != string(secret) || parsed.Get("next") != "1" {
		t.Errorf("参数结构被 Secret 改变了: %#v", parsed)
	}
}

// ── 测试 7：Secret 缺失是 config_error，且错误不含 Secret ───────

func TestResolve_MissingSecretIsConfigErrorWithoutLeak(t *testing.T) {
	endpoint := canonicalEndpoint(model.EndpointMessages)
	endpoint.FixedQueryTemplate = "key={{SECRET:site-token}}"

	err := resolveErr(t, ResolveInput{
		Upstream: testUpstream(), Endpoint: endpoint,
		Values: staticValues{}, // 解析不出来
	})
	if !strings.Contains(err.Error(), "site-token") {
		t.Errorf("错误应指名缺失的 Secret，得到 %v", err)
	}
}

// 值解析失败时，Resolver 不得把下层错误携带的明文再拼进自己的错误。
//
// 这条错误会一路流进 route_health.last_error（落库）并显示在管理界面上，
// 所以「错误里带明文」等于把 Secret 同时写进数据库和 UI。
func TestResolve_ErrorNeverEchoesSecretPlaintext(t *testing.T) {
	const plain = "super-secret-value"
	endpoint := canonicalEndpoint(model.EndpointMessages)
	endpoint.FixedQueryTemplate = "key={{SECRET:site-token}}"

	err := resolveErr(t, ResolveInput{
		Upstream: testUpstream(), Endpoint: endpoint,
		Values: leakyValues{plain: plain},
	})
	if !strings.Contains(err.Error(), "site-token") {
		t.Errorf("错误应指名占位符，得到 %v", err)
	}
	if strings.Contains(err.Error(), plain) {
		t.Errorf("错误文本泄露了 Secret 明文: %v", err)
	}
}

// leakyValues 是一个「把明文写进自己错误里」的恶劣实现。
// 用它是为了证明 Resolver 不会盲目转发下层错误文本。
type leakyValues struct{ plain string }

func (values leakyValues) ResolveValue(_ context.Context, name string) (ResolvedValue, error) {
	return ResolvedValue{}, errors.New("secret store 拒绝返回 " + values.plain)
}

// ── 测试 8：HostOverride 只进 RequestHost 并参与 hash ──────────

func TestResolve_HostOverride(t *testing.T) {
	up := testUpstream()
	up.HostOverride = "real.example:8443"
	got := resolve(t, ResolveInput{Upstream: up, Endpoint: canonicalEndpoint(model.EndpointMessages)})

	if got.RequestHost != "real.example:8443" {
		t.Errorf("RequestHost 应为 override，得到 %q", got.RequestHost)
	}
	// 关键：URL 本身不能被改写 —— 改了就是把流量打到另一个 IP
	if got.RawURL != "https://a.example/v1/messages" {
		t.Errorf("HostOverride 不能改变 URL，得到 %q", got.RawURL)
	}

	plain := resolve(t, ResolveInput{Upstream: testUpstream(), Endpoint: canonicalEndpoint(model.EndpointMessages)})
	if got.ResolvedURLHash == plain.ResolvedURLHash {
		t.Error("HostOverride 必须参与配置 hash")
	}
}

func TestResolve_RejectsBadHostOverride(t *testing.T) {
	cases := []string{
		"https://real.example",
		"real.example/path",
		"real.example?x=1",
		"key@real.example",
		"real example",
		" real.example",
		"real.example\r\n",
		"real.example\x00",
		"real.example\x1f",
		"real.example:notaport",
		"real.example:",
	}
	for _, override := range cases {
		t.Run(override, func(t *testing.T) {
			up := testUpstream()
			up.HostOverride = override
			resolveErr(t, ResolveInput{Upstream: up, Endpoint: canonicalEndpoint(model.EndpointMessages)})
		})
	}
}

// ── 测试 9：ResolvedURLHash 的稳定性与敏感度 ───────────────────

func TestResolve_ResolvedURLHashIdentity(t *testing.T) {
	build := func(mutate func(*model.ProbeUpstreamConfig, *model.UpstreamEndpoint), incoming string,
		values ValueResolver) ResolvedTarget {

		up, endpoint := testUpstream(), canonicalEndpoint(model.EndpointMessages)
		if mutate != nil {
			mutate(up, endpoint)
		}
		return resolve(t, ResolveInput{
			Upstream: up, Endpoint: endpoint, IncomingRawQuery: incoming, Values: values,
		})
	}

	baseline := build(nil, "", nil)
	if again := build(nil, "", nil); again.ResolvedURLHash != baseline.ResolvedURLHash {
		t.Error("相同输入的 ResolvedURLHash 必须稳定")
	}

	// 普通入站 query 只改变 RequestURLHash，不能改变配置 hash ——
	// 否则一个 ?beta=true 就会把同一端点抖成两份全局能力状态。
	withQuery := build(nil, "beta=true", nil)
	if withQuery.ResolvedURLHash != baseline.ResolvedURLHash {
		t.Error("IncomingRawQuery 不能改变 ResolvedURLHash")
	}
	if withQuery.RequestURLHash == baseline.RequestURLHash {
		t.Error("IncomingRawQuery 必须改变 RequestURLHash")
	}

	// 固定 query 配置改变必须改变配置 hash
	fixed := build(func(_ *model.ProbeUpstreamConfig, endpoint *model.UpstreamEndpoint) {
		endpoint.FixedQueryTemplate = "beta=true"
	}, "", nil)
	if fixed.ResolvedURLHash == baseline.ResolvedURLHash {
		t.Error("FixedQueryTemplate 改变必须改变 ResolvedURLHash")
	}
}

// Secret 明文变化只能通过 revision 影响配置 hash。
//
// 反过来说：同一个 revision 下换明文**不能**改变 hash（那意味着明文
// 被喂进了 hash，而配置 hash 是裸 SHA-256 —— 低熵值就成了枚举 oracle）。
func TestResolve_SecretAffectsHashOnlyViaRevision(t *testing.T) {
	endpoint := canonicalEndpoint(model.EndpointMessages)
	endpoint.FixedQueryTemplate = "key={{SECRET:site-token}}"

	hashFor := func(plain string, revision int64) string {
		return resolve(t, ResolveInput{
			Upstream: testUpstream(), Endpoint: endpoint,
			// key 是**完整占位符名**：probetemplate 传给 ValueResolver 的是
			// "SECRET:site-token" 而不是剥掉前缀的名字，剥前缀是 Values 的事。
			Values: staticValues{"SECRET:site-token": {Plain: []byte(plain), Revision: revision}},
		}).ResolvedURLHash
	}

	if hashFor("value-a", 7) != hashFor("value-b", 7) {
		t.Error("同 revision 换明文不得改变配置 hash（否则明文进了裸 SHA）")
	}
	if hashFor("value-a", 7) == hashFor("value-a", 8) {
		t.Error("Secret revision 改变必须改变配置 hash")
	}
}

// ── 测试 10：RequestURLHash 不是裸 SHA-256 ─────────────────────

func TestResolve_RequestURLHashIsKeyed(t *testing.T) {
	input := ResolveInput{
		Upstream: testUpstream(), Endpoint: canonicalEndpoint(model.EndpointMessages),
		Use: ResolveRealForward,
	}
	first, err := NewResolver(fakeHasher{keyID: "k1"}).Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewResolver(fakeHasher{keyID: "k1"}).Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewResolver(fakeHasher{keyID: "k2"}).Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}

	if first.RequestURLHash != same.RequestURLHash {
		t.Error("同 URL + 同 digest key 必须稳定")
	}
	if first.RequestURLHash == other.RequestURLHash {
		t.Error("不同 digest key 必须给出不同摘要")
	}
	if !strings.HasPrefix(first.RequestURLHash, "k1:") {
		t.Errorf("摘要应携带非敏感 key ID，得到 %q", first.RequestURLHash)
	}
	// 配置 hash 与请求 hash 不能是同一个值：前者要跨进程复现（裸 SHA），
	// 后者必须带密钥。相等说明其中一个用错了算法。
	if first.RequestURLHash == first.ResolvedURLHash {
		t.Error("RequestURLHash 与 ResolvedURLHash 不能相同")
	}
}

// ── 测试 11：legacy_exact ────────────────────────────────────

func legacyEndpoint(kind model.EndpointKind, multiProtocol bool) *model.UpstreamEndpoint {
	return &model.UpstreamEndpoint{
		ID: 2, UpstreamID: 10, Kind: kind,
		URLMode:               model.EndpointURLLegacyExact,
		LegacyFullURLID:       55,
		LegacyFullURLRevision: 2,
		LegacyCompatRealOnly:  multiProtocol,
		NeedsReview:           true,
		AuthProfile: model.EndpointAuthProfile{
			Mode: model.AuthModeLegacyAutoRealOnly, SecretRef: "upstream_api_key", Revision: 1,
		},
		Revision: 6,
	}
}

// 单协议 legacy_exact：解密后不拼 canonical path，escaped path 与 query 原样。
func TestResolve_LegacyExactKeepsCapturedURL(t *testing.T) {
	legacy := &fakeLegacy{id: 55, revision: 2,
		plain: "https://a.example/weird%2Fpath/v1?key=abc+def&z=%2F"}

	got := resolve(t, ResolveInput{
		Upstream: testUpstream(), Endpoint: legacyEndpoint(model.EndpointMessages, false),
		LegacyURLs: legacy, IncomingRawQuery: "beta=true",
	})

	const want = "https://a.example/weird%2Fpath/v1?key=abc+def&z=%2F&beta=true"
	if got.RawURL != want {
		t.Errorf("legacy exact URL 必须逐字节保留\nwant %q\ngot  %q", want, got.RawURL)
	}
	if legacy.calls != 1 {
		t.Errorf("应按 expected revision 解密恰好一次，得到 %d 次", legacy.calls)
	}
}

// 多协议 legacy 记录：真实流量继续走 exact URL，合成探活 fail closed。
func TestResolve_LegacyMultiProtocolFailsClosedForSyntheticProbe(t *testing.T) {
	for _, kind := range []model.EndpointKind{
		model.EndpointMessages, model.EndpointResponses,
		model.EndpointChatCompletions, model.EndpointCountTokens,
	} {
		t.Run(string(kind), func(t *testing.T) {
			endpoint := legacyEndpoint(kind, true)

			real := &fakeLegacy{id: 55, revision: 2, plain: "https://a.example/legacy/entry"}
			got := resolve(t, ResolveInput{
				Upstream: testUpstream(), Endpoint: endpoint,
				LegacyURLs: real, Use: ResolveRealForward,
			})
			if got.RawURL != "https://a.example/legacy/entry" {
				t.Errorf("真实流量应保持旧 exact URL，得到 %q", got.RawURL)
			}

			probe := &fakeLegacy{id: 55, revision: 2, plain: "https://a.example/legacy/entry"}
			_, err := newTestResolver().Resolve(context.Background(), ResolveInput{
				Upstream: testUpstream(), Endpoint: endpoint,
				LegacyURLs: probe, Use: ResolveSyntheticProbe,
			})
			if !errors.Is(err, ErrLegacyNeedsReview) {
				t.Fatalf("合成探活应 fail closed，得到 %v", err)
			}
			// 不发网络的前提是连解密都不做：解密本身没有网络 IO，但它是
			// 「准备发请求」的第一步，走到那里说明 fail closed 判早退位置不对。
			if probe.calls != 0 {
				t.Errorf("fail closed 时不应解密 legacy URL，却调用了 %d 次", probe.calls)
			}
		})
	}
}

// legacy_exact 的配置 hash 只纳入 ID/revision，不含解密后的 path/query。
func TestResolve_LegacyHashExcludesDecryptedURL(t *testing.T) {
	hashFor := func(plain string) string {
		return resolve(t, ResolveInput{
			Upstream: testUpstream(), Endpoint: legacyEndpoint(model.EndpointMessages, false),
			LegacyURLs: &fakeLegacy{id: 55, revision: 2, plain: plain},
		}).ResolvedURLHash
	}
	if hashFor("https://a.example/one?key=aaa") != hashFor("https://a.example/two?key=bbb") {
		t.Error("解密后的 path/query 不得进入裸 SHA 配置 hash")
	}
}

func TestResolve_LegacyRejectsCrossOriginAndMissingRef(t *testing.T) {
	// 跨 origin 的 legacy 记录必须拒绝：Reachability 是站级结论
	resolveErr(t, ResolveInput{
		Upstream: testUpstream(), Endpoint: legacyEndpoint(model.EndpointMessages, false),
		LegacyURLs: &fakeLegacy{id: 55, revision: 2, plain: "https://elsewhere.example/v1"},
	})

	// 缺引用
	endpoint := legacyEndpoint(model.EndpointMessages, false)
	endpoint.LegacyFullURLID = 0
	resolveErr(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint,
		LegacyURLs: &fakeLegacy{id: 55, revision: 2, plain: "https://a.example/v1"}})

	// revision 不匹配（store 侧返回冲突）
	stale := legacyEndpoint(model.EndpointMessages, false)
	stale.LegacyFullURLRevision = 99
	resolveErr(t, ResolveInput{Upstream: testUpstream(), Endpoint: stale,
		LegacyURLs: &fakeLegacy{id: 55, revision: 2, plain: "https://a.example/v1"}})
}

// ── 测试 12：legacy l1_path 行为不回归 ────────────────────────

// 旧 Prober 的 L1 有两种形态：l1_path 非空时 GET base+path，为空时 HEAD base。
// 迁移把前者存成 models endpoint 的 url_override，后者存成空 override。
// 这条测试钉住两者解析出来的 URL 与旧行为一致。
func TestResolve_LegacyL1PathBehavior(t *testing.T) {
	cases := []struct {
		name     string
		override string
		want     string
	}{
		{"自定义 l1_path", "https://a.example/status", "https://a.example/status"},
		{"默认 /v1/models", "", "https://a.example/v1/models"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			endpoint := canonicalEndpoint(model.EndpointModels)
			endpoint.URLOverride = c.override
			got := resolve(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint})
			if got.RawURL != c.want {
				t.Errorf("want %q got %q", c.want, got.RawURL)
			}
		})
	}
}

// ── 输入契约 ────────────────────────────────────────────────

func TestResolve_RejectsMismatchedInputs(t *testing.T) {
	t.Run("endpoint 属于别的 upstream", func(t *testing.T) {
		endpoint := canonicalEndpoint(model.EndpointMessages)
		endpoint.UpstreamID = 99
		resolveErr(t, ResolveInput{Upstream: testUpstream(), Endpoint: endpoint})
	})
	t.Run("use 未指定", func(t *testing.T) {
		_, err := newTestResolver().Resolve(context.Background(), ResolveInput{
			Upstream: testUpstream(), Endpoint: canonicalEndpoint(model.EndpointMessages),
		})
		if err == nil {
			t.Fatal("未指定 use 应失败，避免默认落到宽松的一侧")
		}
	})
	t.Run("缺 hasher", func(t *testing.T) {
		_, err := NewResolver(nil).Resolve(context.Background(), ResolveInput{
			Upstream: testUpstream(), Endpoint: canonicalEndpoint(model.EndpointMessages),
			Use: ResolveRealForward,
		})
		if err == nil {
			t.Fatal("没有 hasher 时不能静默产出空摘要")
		}
	})
}

// 确认 ValueResolver 是 probetemplate 的别名（不成环的前提）。
func TestValueResolverIsProbetemplateAlias(t *testing.T) {
	var _ ValueResolver = probetemplate.ValueResolver(staticValues{})
	var _ probetemplate.ResolvedValue = ResolvedValue{}
}
