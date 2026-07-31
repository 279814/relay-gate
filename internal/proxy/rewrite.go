// Package proxy 实现严格透传：除鉴权头与 body 顶层 model 外，一个字节都不改。
package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrNoModelField 表示 body 里没有顶层 model 字段。
//
// 这不一定是错误：count_tokens 之外的端点都带 model，但如果客户端就是没带，
// 我们**不应该替它加**（那是往 body 里增内容，违反 §3.3）。调用方据此决定
// 是原样转发还是回 400。
var ErrNoModelField = errors.New("body 中没有顶层 model 字段")

// ExtractModel 只读出 body 顶层的 model 值，不做任何修改。
// 选路阶段用它来匹配 ModelName。
//
// 返回的是 Go string，因此非法 UTF-8 字节会被 JSON 解码器替换成 U+FFFD。
// 这不影响透传保真：本函数的结果**只用于匹配**（匹配不上就 404），
// 而 ReplaceModel 写入的值来自数据库里已校验的 Route.UpstreamModel，
// 从不回写客户端传来的值。body 字节本身在不映射时完全不经过这里。
func ExtractModel(body []byte) (string, error) {
	start, end, err := locateTopLevelModel(body)
	if err != nil {
		return "", err
	}
	raw := bytes.TrimSpace(body[start:end])
	// 必须显式确认它是 JSON 字符串。不能只靠 Unmarshal 到 string 判断：
	// json.Unmarshal([]byte("null"), &s) 是**空操作**，返回 ("", nil) 而不报错，
	// 空 model 会一路流进选路并静默匹配到兜底。
	if len(raw) == 0 || raw[0] != '"' {
		return "", fmt.Errorf("顶层 model 的值不是字符串（收到 %s）", raw)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("解析 model 的值: %w", err)
	}
	return s, nil
}

// ReplaceModel 把 body 顶层 model 的值换成 newModel，其余字节**原样保留**。
//
// 不能用「反序列化 → 改 → 重新序列化」：encoding/json 的 round-trip 会
// 改变 key 顺序、把 1.0 写成 1、重写 Unicode 转义、丢弃重复 key。
// 任何一条都可能改变上游行为。所以这里只做字节切片拼接。
//
// 契约：**newModel == "" 表示「不映射」**，直接返回原 slice（不复制），
// 对应 Route.UpstreamModel 留空的默认配置（§3.3.2）。
// 因此本函数**无法把 model 改成空字符串** —— 这是刻意的：
// 「映射到空模型名」没有任何合法用途，而「不映射」是最常用的路径，
// 让后者零成本比支持前者更有价值。
//
// 反方向（把空的 model 改成真实模型名）是支持的，见 ExtractModel。
func ReplaceModel(body []byte, newModel string) ([]byte, error) {
	if newModel == "" {
		return body, nil
	}
	start, end, err := locateTopLevelModel(body)
	if err != nil {
		return nil, err
	}

	quoted, err := encodeJSONString(newModel)
	if err != nil {
		return nil, fmt.Errorf("序列化新模型名 %q: %w", newModel, err)
	}

	out := make([]byte, 0, len(body)-(end-start)+len(quoted))
	out = append(out, body[:start]...)
	out = append(out, quoted...)
	out = append(out, body[end:]...)
	return out, nil
}

// locateTopLevelModel 返回顶层 "model" 键的**值**在 body 中的字节区间 [start, end)。
//
// 必须用流式 token 扫描而不是正则或 bytes.Index：body 里嵌套的
// "messages":[{"model":"x"}]、"metadata":{"model":"y"}、
// "tools":[{"input_schema":{"properties":{"model":{}}}}] 都含同名键，
// 只有深度感知的扫描才能区分。
//
// 用 Decoder.Token() 逐个读 token，靠 InputOffset() 拿到偏移量：
// 读到 key 后 offset 落在 key 的右引号之后，读到 value 后 offset 落在 value 之后。
// 值的起点则由「读 value 前的 offset + 跳过空白」得到。
func locateTopLevelModel(body []byte) (start, end int, err error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	// UseNumber 避免把数字转成 float64 —— 我们只关心偏移量，
	// 但转换过程可能对超长数字报错，白白失败。
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return 0, 0, fmt.Errorf("解析 body: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return 0, 0, fmt.Errorf("body 顶层不是 JSON 对象")
	}

	for dec.More() {
		// 读键。此时 InputOffset() 停在键的右引号之后。
		keyTok, err := dec.Token()
		if err != nil {
			return 0, 0, fmt.Errorf("解析 body 键: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return 0, 0, fmt.Errorf("JSON 对象键不是字符串")
		}
		afterKey := int(dec.InputOffset())

		if key != "model" {
			// 跳过整个值（含嵌套结构）。Decode 到 RawMessage 会消费掉
			// 完整的一个值，比手工数括号可靠。
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return 0, 0, fmt.Errorf("跳过 %q 的值: %w", key, err)
			}
			continue
		}

		// 命中顶层 model。值的起点 = 键后的冒号与空白之后。
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return 0, 0, fmt.Errorf("解析 model 的值: %w", err)
		}
		end = int(dec.InputOffset())

		// 从 end 往回退 len(raw) 得到值的起点。
		// Decoder 缓冲的是原始字节，RawMessage 保留原文（含内部空白），
		// 所以这个减法是精确的，不必自己跳空白。
		start = end - len(raw)
		if start < afterKey || start > len(body) || end > len(body) {
			return 0, 0, fmt.Errorf("定位 model 值失败：区间 [%d,%d) 不合法", start, end)
		}
		return start, end, nil
	}
	return 0, 0, ErrNoModelField
}

// encodeJSONString 把字符串编码成 JSON 字符串字面量，且**不做 HTML 转义**。
//
// 两处不能用现成方案：
//   - strconv.Quote 按 **Go 语法**转义（DEL → \x7f），JSON 不认识 \x，产出非法 JSON
//   - json.Marshal 默认开 HTML 转义，把 < > & 写成 < > & ——
//     JSON 合法、语义相同，但**字节不同**。对以字节保真为目的的透传网关，
//     这个默认行为不合适
//
// Encoder 会在末尾追加换行，需要去掉。
func encodeJSONString(s string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ReadBodyLimited 读取整个 body，超过 limit 返回错误。
//
// 必须整体读入内存：改 model 需要定位偏移量，无法流式改写；
// 且失败重试（§3.5）要求能重放 body。limit 防的是超大请求打爆内存。
func ReadBodyLimited(r io.Reader, limit int64) ([]byte, error) {
	// 多读 1 字节以区分「正好等于上限」和「超过上限」
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("请求体超过上限 %d 字节", limit)
	}
	return b, nil
}
