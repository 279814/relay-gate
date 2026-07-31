package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// 不映射是默认且推荐的路径（M0 实测各站模型名原名均可用）。
// 此时必须连拷贝都不做，原样返回同一个 slice。
func TestReplaceModel_NoMappingReturnsSameSlice(t *testing.T) {
	in := []byte(`{"model":"claude-opus-5","max_tokens":1}`)
	out, err := ReplaceModel(in, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("不映射时必须字节完全一致\n in: %s\nout: %s", in, out)
	}
	if &out[0] != &in[0] {
		t.Error("不映射时应返回原 slice 本身，不该产生拷贝")
	}
}

// 核心保真断言：映射后把 model 值换回原值，必须与原始 body 逐字节相同。
// 这条比「语义等价」强得多 —— 它能抓出 key 重排、数值改写、转义变化等
// 所有 JSON round-trip 会引入的劣化。
func TestReplaceModel_RoundTripIsByteIdentical(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"最简", `{"model":"claude-opus-5"}`},
		{
			// round-trip 会按字典序重排 key，这里 model 在中间，重排必被发现
			"key 顺序（model 在中间）",
			`{"max_tokens":1,"model":"claude-opus-5","stream":true}`,
		},
		{
			// Marshal 会把 1.0 写成 1、1e5 写成 100000
			"数值字面量形式",
			`{"model":"m","temperature":1.0,"top_p":0.70,"n":1e5,"big":12345678901234567890}`,
		},
		{
			// Marshal 会把 é 还原成 é
			"Unicode 转义形式",
			`{"model":"m","text":"café 中文 😀"}`,
		},
		{
			// Unmarshal 到 map 只会留最后一个
			"重复 key",
			`{"model":"m","a":1,"a":2}`,
		},
		{
			// null 与字段缺失在 map 里都是零值，无法区分
			"null 与缺失的区别",
			`{"model":"m","stop_sequences":null,"metadata":{}}`,
		},
		{
			"空白与缩进",
			"{\n  \"model\" : \"claude-opus-5\" ,\n  \"max_tokens\" : 1\n}",
		},
		{
			"未知字段（未来的新参数）",
			`{"model":"m","some_future_param":{"nested":[1,2,3]}}`,
		},
		{
			"转义引号与反斜杠",
			`{"model":"m","s":"he said \"hi\" and \\ then \/ left\n\t"}`,
		},
		{
			"空对象与空数组",
			`{"model":"m","tools":[],"metadata":{}}`,
		},
		{
			"深层嵌套",
			`{"model":"m","tools":[{"input_schema":{"properties":{"a":{"type":"string"}}}}]}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := []byte(c.body)
			orig, err := ExtractModel(in)
			if err != nil {
				t.Fatalf("提取 model 失败: %v", err)
			}

			mapped, err := ReplaceModel(in, "upstream-model-name-xyz")
			if err != nil {
				t.Fatalf("替换失败: %v", err)
			}
			if got, _ := ExtractModel(mapped); got != "upstream-model-name-xyz" {
				t.Fatalf("替换后 model 应为新值，得到 %q", got)
			}

			back, err := ReplaceModel(mapped, orig)
			if err != nil {
				t.Fatalf("换回失败: %v", err)
			}
			if !bytes.Equal(back, in) {
				t.Errorf("换回原值后应与原始 body 逐字节相同\n原始: %s\n换回: %s", in, back)
			}
		})
	}
}

// 只能改深度 0 的 model。body 里嵌套的同名字段必须原封不动 ——
// 改错地方会篡改工具定义或历史消息，且症状极其隐蔽。
func TestReplaceModel_OnlyTopLevel(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			"messages 里的 model",
			`{"model":"TOP","messages":[{"role":"user","model":"NESTED","content":"hi"}]}`,
		},
		{
			"metadata 里的 model",
			`{"model":"TOP","metadata":{"model":"NESTED","user_id":"u1"}}`,
		},
		{
			"tools 的 JSON Schema 里名为 model 的属性",
			`{"model":"TOP","tools":[{"input_schema":{"properties":{"model":{"type":"string"}}}}]}`,
		},
		{
			"顶层 model 出现在嵌套 model 之后",
			`{"messages":[{"model":"NESTED"}],"model":"TOP"}`,
		},
		{
			"数组里多层嵌套的 model",
			`{"model":"TOP","a":[[{"model":"NESTED"}]]}`,
		},
		{
			"字符串值里恰好含 model 字样",
			`{"model":"TOP","system":"you must set \"model\":\"NESTED\" in output"}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := []byte(c.body)
			if got, _ := ExtractModel(in); got != "TOP" {
				t.Fatalf("应提取到顶层的 TOP，得到 %q", got)
			}

			out, err := ReplaceModel(in, "REPLACED")
			if err != nil {
				t.Fatal(err)
			}
			s := string(out)
			if strings.Count(s, "NESTED") != strings.Count(c.body, "NESTED") {
				t.Errorf("嵌套的 NESTED 被改动了\n原始: %s\n结果: %s", c.body, s)
			}
			if strings.Contains(s, `"TOP"`) {
				t.Errorf("顶层 model 未被替换\n结果: %s", s)
			}
			if !strings.Contains(s, "REPLACED") {
				t.Errorf("未写入新值\n结果: %s", s)
			}
		})
	}
}

// 大 body（含 base64 图片）是真实场景，要确保偏移量计算不会在大输入上出错。
func TestReplaceModel_LargeBody(t *testing.T) {
	img := strings.Repeat("iVBORw0KGgoAAAANSUhEUg", 20000) // ~440KB
	in := []byte(`{"model":"claude-opus-5","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","data":"` + img + `"}}]}],"max_tokens":1}`)

	out, err := ReplaceModel(in, "mapped")
	if err != nil {
		t.Fatal(err)
	}
	back, err := ReplaceModel(out, "claude-opus-5")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, in) {
		t.Error("大 body 往返后不一致")
	}
	if !json.Valid(out) {
		t.Error("替换后不是合法 JSON")
	}
}

// 新模型名含需要转义的字符时，必须正确转义后再写入，否则会产出非法 JSON。
func TestReplaceModel_EscapesNewValue(t *testing.T) {
	in := []byte(`{"model":"m"}`)
	for _, name := range []string{
		`with"quote`,
		`with\backslash`,
		"with\nnewline",
		"中文模型名",
		"with\ttab",
	} {
		out, err := ReplaceModel(in, name)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if !json.Valid(out) {
			t.Errorf("%q 替换后不是合法 JSON: %s", name, out)
		}
		got, err := ExtractModel(out)
		if err != nil {
			t.Fatalf("%q: 回读失败 %v", name, err)
		}
		if got != name {
			t.Errorf("回读不一致: want %q got %q", name, got)
		}
	}
}

func TestExtractModel_Errors(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr error
	}{
		{"无 model 字段", `{"max_tokens":1}`, ErrNoModelField},
		{"空对象", `{}`, ErrNoModelField},
		{"只有嵌套 model", `{"messages":[{"model":"x"}]}`, ErrNoModelField},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ExtractModel([]byte(c.body))
			if !errors.Is(err, c.wantErr) {
				t.Errorf("want %v, got %v", c.wantErr, err)
			}
		})
	}

	// 非法输入必须报错而不是 panic 或静默返回错误结果
	for _, body := range []string{
		``, `[]`, `"str"`, `123`, `null`,
		`{`, `{"model":}`, `{"model":"unterminated`,
		`{"model":123}`,  // 数字型 model，ExtractModel 应报类型错
		`{"model":null}`, // null 型
	} {
		t.Run("非法/异常输入 "+body, func(t *testing.T) {
			if _, err := ExtractModel([]byte(body)); err == nil {
				t.Errorf("%q 应报错", body)
			}
		})
	}
}

// ReplaceModel 在 body 无 model 字段时必须报错，
// **绝不能替客户端补一个** —— 那是往 body 里增内容，违反 §3.3。
func TestReplaceModel_DoesNotInjectMissingField(t *testing.T) {
	in := []byte(`{"max_tokens":1}`)
	out, err := ReplaceModel(in, "some-model")
	if !errors.Is(err, ErrNoModelField) {
		t.Fatalf("应返回 ErrNoModelField，得到 %v", err)
	}
	if out != nil {
		t.Errorf("出错时不应返回 body，得到 %s", out)
	}
}

func TestReadBodyLimited(t *testing.T) {
	data := strings.Repeat("x", 100)

	if b, err := ReadBodyLimited(strings.NewReader(data), 100); err != nil || len(b) != 100 {
		t.Errorf("正好等于上限应通过，得到 len=%d err=%v", len(b), err)
	}
	if _, err := ReadBodyLimited(strings.NewReader(data), 99); err == nil {
		t.Error("超过上限应报错")
	}
	if b, err := ReadBodyLimited(strings.NewReader(""), 10); err != nil || len(b) != 0 {
		t.Errorf("空 body 应正常返回，得到 len=%d err=%v", len(b), err)
	}
}

// 模糊测试的不变量：**除 model 值区间外，所有字节逐一相同**。
//
// 这比「换过去再换回来 == 原文」准确。后者会被 JSON 字符串的等价表示
// 干扰（`\/` 与 `/`、`A` 与 `A` 都合法且等价，解码再编码必然收敛到
// 其中一种），而那个操作**生产路径并不存在** —— 写入的值永远来自数据库里
// 的 Route.UpstreamModel，从不是从 body 解出来的再写回。
//
// 本不变量直接对应 §3.3 的硬约束，且把「值被替换」与「其余字节不变」
// 分开验证，比往返断言更强。
func FuzzReplaceModelPreservesOtherBytes(f *testing.F) {
	f.Add(`{"model":"a","x":1}`)
	f.Add(`{"x":{"model":"nested"},"model":"a"}`)
	f.Add(`{"model":"a","n":1.0,"s":"é"}`)
	f.Add(`{"model":"\/","a":"A"}`)
	f.Add(`{"model" : "a" , "b":[1,{"model":2}]}`)

	const newModel = "MAPPED-UPSTREAM-NAME"

	f.Fuzz(func(t *testing.T, body string) {
		in := []byte(body)
		start, end, err := locateTopLevelModel(in)
		if err != nil {
			return // 无顶层 model 或非法 JSON，不是本测试的目标
		}
		// 只测字符串型 model —— 非字符串会被 ExtractModel 拒绝，
		// 上层不会走到替换
		if raw := bytes.TrimSpace(in[start:end]); len(raw) == 0 || raw[0] != '"' {
			return
		}

		out, err := ReplaceModel(in, newModel)
		if err != nil {
			t.Fatalf("定位成功但替换失败: %v (body=%q)", err, body)
		}

		// 1. model 值之前的字节：逐一相同
		if !bytes.Equal(out[:start], in[:start]) {
			t.Errorf("model 值之前的字节被改动了\n原始: %q\n结果: %q", in[:start], out[:start])
		}

		// 2. model 值之后的字节：逐一相同
		quoted, err := encodeJSONString(newModel)
		if err != nil {
			t.Fatal(err)
		}
		gotTail := out[start+len(quoted):]
		wantTail := in[end:]
		if !bytes.Equal(gotTail, wantTail) {
			t.Errorf("model 值之后的字节被改动了\n原始: %q\n结果: %q", wantTail, gotTail)
		}

		// 3. model 值本身：确实换成了新值
		if got := out[start : start+len(quoted)]; !bytes.Equal(got, quoted) {
			t.Errorf("model 值未被正确替换\nwant %q\ngot  %q", quoted, got)
		}

		// 4. 结果仍是合法 JSON（原输入合法时）
		if json.Valid(in) && !json.Valid(out) {
			t.Errorf("合法输入产出了非法 JSON\n原始: %q\n结果: %q", body, out)
		}
	})
}

// 规范形式输入的往返测试。输入限定为「解码再编码不会变形」的规范 JSON
// 字符串，此时往返必须字节还原 —— 这是对表驱动用例的随机化补充。
func FuzzReplaceModelRoundTrip(f *testing.F) {
	f.Add(`{"model":"a","x":1}`)
	f.Add(`{"x":{"model":"nested"},"model":"a"}`)
	f.Add(`{"model":"a","n":1.0,"s":"é"}`)

	f.Fuzz(func(t *testing.T, body string) {
		in := []byte(body)
		start, end, err := locateTopLevelModel(in)
		if err != nil {
			return
		}
		orig, err := ExtractModel(in)
		if err != nil || orig == "" {
			// 非字符串型 model 上层会拒绝；空值时 "" 参数含义是「不映射」
			return
		}
		// 只在**规范形式**下断言字节还原：原文里的 model 值必须与
		// 「解码再编码」的结果一致。否则等价写法（\/ 与 /、A 与 A）
		// 会必然收敛到一种，往返不可能字节相同 —— 那是 JSON 的性质，
		// 不是本函数的缺陷。非规范形式由
		// FuzzReplaceModelPreservesOtherBytes 覆盖。
		canonical, err := encodeJSONString(orig)
		if err != nil || !bytes.Equal(in[start:end], canonical) {
			return
		}

		mapped, err := ReplaceModel(in, "TEMP-MAPPED-NAME")
		if err != nil {
			t.Fatalf("定位成功但替换失败: %v (body=%q)", err, body)
		}
		back, err := ReplaceModel(mapped, orig)
		if err != nil {
			t.Fatalf("换回失败: %v (body=%q)", err, body)
		}
		if !bytes.Equal(back, in) {
			t.Errorf("规范形式下往返应字节还原\n原始: %q\n换回: %q", body, back)
		}
	})
}

// HTML 转义必须关闭：json.Marshal 默认把 < > & 写成 < > &，
// 虽然 JSON 合法且语义相同，但字节不同。对以字节保真为目的的网关不合适。
func TestEncodeJSONStringNoHTMLEscape(t *testing.T) {
	for _, s := range []string{"a<b", "a>b", "a&b", "<script>", "a&b<c>d"} {
		got, err := encodeJSONString(s)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(got, []byte(`\u00`)) {
			t.Errorf("%q 被 HTML 转义了：%s", s, got)
		}
		var back string
		if err := json.Unmarshal(got, &back); err != nil || back != s {
			t.Errorf("%q 编码后无法还原：%s (%v)", s, got, err)
		}
	}

	// DEL 等控制字符必须走 JSON 的 \u 转义，不能是 Go 的 \x
	got, err := encodeJSONString("\x7f\x01")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte(`\x`)) {
		t.Errorf("产生了 Go 风格的 \\x 转义（JSON 不认识）：%s", got)
	}
	if !json.Valid(got) {
		t.Errorf("控制字符编码后不是合法 JSON：%s", got)
	}
}
