package sample

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRedactHeaders_MasksCredentialsKeepsStructure(t *testing.T) {
	const key = "sk-ant-api03-real-secret-value-here"
	const adminPW = "super-secret-admin-password-value"
	in := http.Header{}
	in.Set("Authorization", "Bearer "+key)
	in.Set("X-Api-Key", key)
	in.Set("Api-Key", key)
	in.Set("Cookie", "session="+key)
	in.Set("X-Admin-Password", adminPW)
	in.Set("User-Agent", "claude-cli/2.1.220 (external, sdk-cli)")
	in.Set("Anthropic-Version", "2023-06-01")

	out := RedactHeaders(in, nil)

	// 凭据一个字都不能留
	for k, vs := range out {
		for _, v := range vs {
			if strings.Contains(v, key) || strings.Contains(v, adminPW) {
				t.Errorf("头 %s 里残留了完整凭据: %q", k, v)
			}
		}
	}
	if out.Get("X-Admin-Password") == "" || out.Get("X-Admin-Password") == adminPW {
		t.Errorf("X-Admin-Password 应脱敏保留头名，得到 %q", out.Get("X-Admin-Password"))
	}
	// 但结构必须保留：调探活时要知道 key 放在哪个头、什么格式（§3.6.3b）
	if got := out.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
		t.Errorf("应保留 Bearer 前缀，得到 %q", got)
	}
	if out.Get("X-Api-Key") == "" {
		t.Error("应保留头名，只脱敏值")
	}
	// 非敏感头必须原样保留 —— 它们正是探活模板要复制的指纹
	if out.Get("User-Agent") != "claude-cli/2.1.220 (external, sdk-cli)" {
		t.Errorf("UA 应原样保留，得到 %q", out.Get("User-Agent"))
	}
	if out.Get("Anthropic-Version") != "2023-06-01" {
		t.Error("普通头应原样保留")
	}
}

// 脱敏绝不能修改原 header —— 它可能还在被转发路径读。
func TestRedactHeaders_DoesNotMutateInput(t *testing.T) {
	const key = "sk-original-secret-key-value"
	in := http.Header{}
	in.Set("X-Api-Key", key)

	RedactHeaders(in, nil)

	if in.Get("X-Api-Key") != key {
		t.Error("脱敏修改了原 header —— 这会影响转发路径")
	}
}

func TestRedactHeaders_NilAndEmpty(t *testing.T) {
	if got := RedactHeaders(nil, nil); got == nil || len(got) != 0 {
		t.Errorf("nil 应返回空 Header 而不是 nil，得到 %v", got)
	}
	if got := RedactHeaders(http.Header{}, nil); len(got) != 0 {
		t.Errorf("空应返回空，得到 %v", got)
	}
}

// 大小写不规范的头名也要脱敏，否则会漏。
func TestRedactHeaders_CaseInsensitive(t *testing.T) {
	const key = "sk-leak-this-key-should-be-masked"
	in := http.Header{
		"authorization": {"Bearer " + key},
		"X-API-KEY":     {key},
		"api-key":       {key},
	}
	out := RedactHeaders(in, nil)
	for k, vs := range out {
		for _, v := range vs {
			if strings.Contains(v, key) {
				t.Errorf("非规范大小写的头 %s 未脱敏: %q", k, v)
			}
		}
	}
}

// 多值头的每个值都要脱敏。
func TestRedactHeaders_AllValuesOfMultiValue(t *testing.T) {
	const k1, k2 = "sk-first-secret-key-here", "sk-second-secret-key-here"
	in := http.Header{"X-Api-Key": {k1, k2}}

	out := RedactHeaders(in, nil)
	if len(out["X-Api-Key"]) != 2 {
		t.Fatalf("应保留 2 个值，得到 %v", out["X-Api-Key"])
	}
	for _, v := range out["X-Api-Key"] {
		if v == k1 || v == k2 {
			t.Errorf("多值头的值未全部脱敏: %q", v)
		}
	}
}

// Non-auth headers still scan known secrets (§5.4): transform secret_ref can
// place the upstream key on X-Custom; name-only masking would leave plaintext.
func TestRedactHeaders_ScansKnownKeysInNonAuthHeaders(t *testing.T) {
	const key = "sk-distinctive-xform-in-custom-hdr"
	in := http.Header{}
	in.Set("X-Site-Token", key)
	in.Set("User-Agent", "keep-me")

	out := RedactHeaders(in, []string{key})
	if strings.Contains(out.Get("X-Site-Token"), key) {
		t.Fatalf("custom header still has raw key: %q", out.Get("X-Site-Token"))
	}
	if out.Get("User-Agent") != "keep-me" {
		t.Fatalf("unrelated header changed: %q", out.Get("User-Agent"))
	}
}

func TestRedactBodyKeys(t *testing.T) {
	const key = "sk-body-embedded-secret-key"
	body := []byte(`{"model":"m","api_key":"` + key + `","system":"hello"}`)

	out := RedactBodyKeys(body, []string{key})
	if strings.Contains(string(out), key) {
		t.Errorf("body 里的 key 未脱敏: %s", out)
	}
	// 其余内容必须完好 —— 脱敏不该破坏对话原文
	if !strings.Contains(string(out), `"system":"hello"`) {
		t.Errorf("非 key 内容被破坏了: %s", out)
	}
}

// 没命中时必须返回原 slice，不做无谓的拷贝。
// 绝大多数请求的 body 里没有 key，这是热路径。
func TestRedactBodyKeys_NoHitReturnsOriginal(t *testing.T) {
	body := []byte(`{"model":"claude-opus-5","max_tokens":1}`)
	out := RedactBodyKeys(body, []string{"sk-not-present-in-this-body"})

	if &out[0] != &body[0] {
		t.Error("未命中时应返回原 slice，避免为绝大多数样本白拷贝")
	}
}

// 太短的 key 不参与 body 扫描：在正常对话里会大量偶然命中，
// 把原文打得千疮百孔，反而毁掉样本的诊断价值。
func TestRedactBodyKeys_SkipsShortKeys(t *testing.T) {
	body := []byte(`{"system":"the cat sat on the mat"}`)
	out := RedactBodyKeys(body, []string{"cat", "at"})

	if string(out) != string(body) {
		t.Errorf("过短的 key 不该参与替换，得到 %s", out)
	}
}

func TestRedactBodyKeys_MultipleKeys(t *testing.T) {
	const relay, up = "rk-relay-client-key-value", "sk-upstream-station-key"
	body := []byte(`{"a":"` + relay + `","b":"` + up + `"}`)

	out := RedactBodyKeys(body, []string{up, relay})
	for _, k := range []string{relay, up} {
		if strings.Contains(string(out), k) {
			t.Errorf("key %q 未脱敏: %s", k, out)
		}
	}
}

// 空 key 与空 body 不能 panic。
func TestRedactBodyKeys_Edges(t *testing.T) {
	if got := RedactBodyKeys(nil, []string{"sk-something-long-enough"}); got != nil {
		t.Errorf("nil body 应返回 nil，得到 %v", got)
	}
	body := []byte(`{}`)
	if got := RedactBodyKeys(body, nil); string(got) != "{}" {
		t.Errorf("空 keys 应原样返回，得到 %s", got)
	}
	if got := RedactBodyKeys(body, []string{""}); string(got) != "{}" {
		t.Errorf("空 key 应被跳过，得到 %s", got)
	}
}

// Location / Content-Location / Refresh / Link 可能回显带 ?key= 的出站 URL。
// 只替凭据值，不动无关 query 与 Link 的 rel=；其它头不碰。
func TestRedactCredentialURLHeaders(t *testing.T) {
	const secret = "sk-upstream-secret-in-query-hdr"
	h := http.Header{}
	h.Set("Location", "https://a.example/x?key="+secret+"&beta=true")
	h.Add("Location", "https://b.example/y?token="+secret)
	h.Set("Link", `<https://a.example/x?key=`+secret+`&beta=true>; rel="next"`)
	h.Set("X-Request-Id", "keep")

	RedactCredentialURLHeaders(h, []string{secret})

	for _, v := range h.Values("Location") {
		if strings.Contains(v, secret) {
			t.Errorf("Location 残留完整 key：%q", v)
		}
	}
	if !strings.Contains(h.Get("Location"), "beta=true") {
		t.Errorf("无关 query 应保留：%q", h.Get("Location"))
	}
	link := h.Get("Link")
	if strings.Contains(link, secret) {
		t.Errorf("Link 残留完整 key：%q", link)
	}
	if !strings.Contains(link, "beta=true") {
		t.Errorf("Link 无关 query 应保留：%q", link)
	}
	if !strings.Contains(link, `rel="next"`) {
		t.Errorf("Link rel 应保留：%q", link)
	}
	if h.Get("X-Request-Id") != "keep" {
		t.Error("非 URL 头不得改写")
	}
	RedactCredentialURLHeaders(nil, []string{secret}) // 不得 panic
	RedactCredentialURLHeaders(h, nil)                // 空 keys 空操作
}

// RedactDiagnosticText must cover QueryEscape forms the same way finding
// Detail does (security.RedactSecrets). Raw-only ReplaceAll would leave the
// encoded key in request-log / probe error text.
func TestRedactDiagnosticText_RedactsQueryEscapedKey(t *testing.T) {
	const key = "sk-diag/OMIT+TEST=KEY-7e4d9a2c"
	enc := url.QueryEscape(key)
	if enc == key {
		t.Fatal("test key must differ under QueryEscape")
	}
	errText := `upstream refused: token=` + enc + ` trail`
	got := RedactDiagnosticText(errText, []string{key})
	if strings.Contains(got, enc) {
		t.Fatalf("stored error still contains query-escaped key: %q", got)
	}
	if strings.Contains(got, key) {
		t.Fatalf("stored error still contains raw key: %q", got)
	}
	if !strings.Contains(got, "upstream refused") || !strings.Contains(got, "trail") {
		t.Fatalf("unrelated error text must stay: %q", got)
	}
}

// RedactDiagnostic (ErrBody / last_error / count_tokens slog) must share
// RedactSecrets encoding coverage — raw ReplaceAll alone leaves QueryEscape,
// lowercase-%XX, and mixed-case JSON \u00XX forms in stored error bodies.
func TestRedactDiagnostic_RedactsEncodedKeyForms(t *testing.T) {
	const key = "sk-diag/OMIT+TEST=KEY-7e4d9a2c"
	enc := url.QueryEscape(key)
	if enc == key {
		t.Fatal("test key must differ under QueryEscape")
	}
	lower := lowerPercentHexForTest(enc)
	if lower == enc {
		t.Fatal("test key QueryEscape form must contain A-F hex digits")
	}
	escMixed := mixedCaseJSONByteUnicodeEscapeForTest(key)
	const unrelatedU = `\u4e2d\u6587`
	const unrelatedPct = `%2Fkeep`
	body := `raw=` + key + ` q=` + enc + ` low=` + lower +
		` u=` + escMixed + ` note=` + unrelatedU + ` pct=` + unrelatedPct + ` trail`
	got := string(RedactDiagnostic([]byte(body), []string{key}))
	for _, leak := range []string{key, enc, lower, escMixed} {
		if strings.Contains(got, leak) {
			t.Fatalf("ErrBody still contains secret form %q in: %q", leak, got)
		}
	}
	if !strings.Contains(got, unrelatedU) {
		t.Fatalf("unrelated \\u sequence must stay: %q", got)
	}
	if !strings.Contains(got, unrelatedPct) {
		t.Fatalf("unrelated percent sequence must stay: %q", got)
	}
	if !strings.Contains(got, "trail") || !strings.Contains(got, "raw=") {
		t.Fatalf("unrelated body text must stay: %q", got)
	}
}

// Short needles (< MinRedactableKeyLen, including "") must not be ReplaceAll
// targets: replacing "key" or "1" would corrupt query URLs in ErrBody / errors.
// Keys at the floor length still disappear.
func TestRedactDiagnostic_SkipsShortSecretNeedles(t *testing.T) {
	const rawURL = "https://example.com/v1/messages?key=1"
	for _, short := range []string{"key", "1", ""} {
		if got := string(RedactDiagnostic([]byte(rawURL), []string{short})); got != rawURL {
			t.Fatalf("short needle %q must leave URL unchanged: got %q", short, got)
		}
		if got := RedactDiagnosticText(rawURL, []string{short}); got != rawURL {
			t.Fatalf("short needle %q must leave error URL unchanged: got %q", short, got)
		}
	}
	const long = "sk-longenough1" // 14 >= MinRedactableKeyLen
	body := rawURL + "&token=" + long
	gotBody := string(RedactDiagnostic([]byte(body), []string{long}))
	if strings.Contains(gotBody, long) {
		t.Fatalf("12+ char secret must disappear from body: %q", gotBody)
	}
	if !strings.Contains(gotBody, rawURL) {
		t.Fatalf("URL with short query tokens must stay: %q", gotBody)
	}
	gotText := RedactDiagnosticText("upstream echo "+body, []string{long})
	if strings.Contains(gotText, long) {
		t.Fatalf("12+ char secret must disappear from error text: %q", gotText)
	}
	if !strings.Contains(gotText, rawURL) {
		t.Fatalf("URL with short query tokens must stay in error text: %q", gotText)
	}
}

// lowerPercentHexForTest mirrors security.percentEncodingLowerHex for the sample test.
func lowerPercentHexForTest(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) && isHexDigitForTest(s[i+1]) && isHexDigitForTest(s[i+2]) {
			b.WriteByte('%')
			b.WriteByte(toLowerHexDigitForTest(s[i+1]))
			b.WriteByte(toLowerHexDigitForTest(s[i+2]))
			i += 3
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func mixedCaseJSONByteUnicodeEscapeForTest(key string) string {
	const hex = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(key) * 6)
	for i := 0; i < len(key); i++ {
		c := key[i]
		hi, lo := hex[c>>4], hex[c&0xf]
		if i%2 == 0 {
			hi = toUpperHexDigitForTest(hi)
			lo = toUpperHexDigitForTest(lo)
		}
		b.WriteString(`\u00`)
		b.WriteByte(hi)
		b.WriteByte(lo)
	}
	return b.String()
}

func isHexDigitForTest(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func toLowerHexDigitForTest(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
}

func toUpperHexDigitForTest(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - ('a' - 'A')
	}
	return c
}
