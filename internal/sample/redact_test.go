package sample

import (
	"net/http"
	"strings"
	"testing"
)

func TestRedactHeaders_MasksCredentialsKeepsStructure(t *testing.T) {
	const key = "sk-ant-api03-real-secret-value-here"
	in := http.Header{}
	in.Set("Authorization", "Bearer "+key)
	in.Set("X-Api-Key", key)
	in.Set("Api-Key", key)
	in.Set("Cookie", "session="+key)
	in.Set("User-Agent", "claude-cli/2.1.220 (external, sdk-cli)")
	in.Set("Anthropic-Version", "2023-06-01")

	out := RedactHeaders(in)

	// 凭据一个字都不能留
	for k, vs := range out {
		for _, v := range vs {
			if strings.Contains(v, key) {
				t.Errorf("头 %s 里残留了完整 key: %q", k, v)
			}
		}
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

	RedactHeaders(in)

	if in.Get("X-Api-Key") != key {
		t.Error("脱敏修改了原 header —— 这会影响转发路径")
	}
}

func TestRedactHeaders_NilAndEmpty(t *testing.T) {
	if got := RedactHeaders(nil); got == nil || len(got) != 0 {
		t.Errorf("nil 应返回空 Header 而不是 nil，得到 %v", got)
	}
	if got := RedactHeaders(http.Header{}); len(got) != 0 {
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
	out := RedactHeaders(in)
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

	out := RedactHeaders(in)
	if len(out["X-Api-Key"]) != 2 {
		t.Fatalf("应保留 2 个值，得到 %v", out["X-Api-Key"])
	}
	for _, v := range out["X-Api-Key"] {
		if v == k1 || v == k2 {
			t.Errorf("多值头的值未全部脱敏: %q", v)
		}
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
