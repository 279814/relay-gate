// Package sample 记录每次转发的三份内容 + 四个时间戳（§3.6）。
//
// 全包的设计前提是**旁路**：记录失败、记录变慢、记录被丢弃，都绝不能影响转发。
// 宁可丢样本，也不让「记日志」拖慢或拖垮转发 —— 这是主次关系，不能倒置。
package sample

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// sensitiveHeaders 是可能携带凭据的头。值一律脱敏后落库（§3.6.3b）。
//
// 不脱敏的话，样本库就是一份明文 key 库，而它比配置表更容易被整体导出
// （配置表的 key 是加密的，样本表的头是明文）。
//
// 脱敏不损害用途：调探活时需要知道的是「key 放在**哪个头**、什么**格式**」，
// 头名与 Bearer 前缀都完整保留，值本身由配置提供。
//
// 由 model.AuthHeaders 派生而不是另抄一份：那份清单是 API key 位置的
// 唯一来源，新增一个位置时这里必须同步，而「忘了同步」的表现是明文 key
// 静默落库 —— 不报错、不失败，只有翻数据库才会发现。
// 这里再多加几项：它们不是 API key 的位置，但同样是凭据。
var sensitiveHeaders = func() map[string]bool {
	m := map[string]bool{
		"Proxy-Authorization": true,
		"Cookie":              true,
		"Set-Cookie":          true,
	}
	for _, h := range model.AuthHeaders {
		m[http.CanonicalHeaderKey(h)] = true
	}
	return m
}()

// RedactHeaders 返回脱敏后的头副本。原 header 不被修改 ——
// 它可能还在被转发路径读，改它就违反了「绝不影响转发」。
func RedactHeaders(h http.Header) http.Header {
	if h == nil {
		return http.Header{}
	}
	out := make(http.Header, len(h))
	for k, vs := range h {
		ck := http.CanonicalHeaderKey(k)
		cp := make([]string, len(vs))
		for i, v := range vs {
			if sensitiveHeaders[ck] {
				cp[i] = redactValue(v)
			} else {
				cp[i] = v
			}
		}
		out[ck] = cp
	}
	return out
}

// redactValue 保留结构、只打码凭据本身。
//
// 保留 "Bearer " 前缀是刻意的：§3.6.4 要把样本导出成探活模板，
// 那时需要知道的正是「这个站用的是 Bearer 还是裸 key」。
func redactValue(v string) string {
	if v == "" {
		return ""
	}
	// scheme 前缀（Bearer / Basic）保留，只脱敏后面的凭据
	if i := strings.IndexByte(v, ' '); i > 0 {
		scheme, cred := v[:i], strings.TrimSpace(v[i+1:])
		if cred != "" {
			return scheme + " " + store.MaskKey(cred)
		}
	}
	return store.MaskKey(v)
}

// RedactBodyKeys 把 body 里出现的完整 key 替换成脱敏形式。
//
// 为什么 body 也要扫：OpenAI 兼容端点允许把 key 放在 body 里，
// 少数中转站的自定义字段也会带上它。§9.4 的验收标准是
// 「用真 key 字符串全表 grep 断言为 0 命中」—— 只清头满足不了。
//
// 全程在 []byte 上操作。走 string 转换的话，每次 `string(body)` 都是一次
// 全量拷贝 —— body 上限 32MB、keys 通常 2~4 个、每条样本调三次，
// 那是几百 MB 的无谓拷贝，而绝大多数样本里一个 key 都不含（§3.6.3a
// 要求采集不拖慢转发，这条路径必须在「没命中」时接近零成本）。
//
// keys 通常只有 2 个（relay key 与该站的上游 key），所以逐个 Replace
// 足够快，不必上 Aho-Corasick。
func RedactBodyKeys(body []byte, keys []string) []byte {
	// 先只做查找，不做替换：绝大多数样本不含 key，这一支直接原样返回，
	// 一个字节都不拷。
	var hit bool
	for _, k := range keys {
		if len(k) >= minRedactableKey && bytes.Contains(body, []byte(k)) {
			hit = true
			break
		}
	}
	if !hit {
		return body
	}

	out := body
	for _, k := range keys {
		if len(k) < minRedactableKey {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(k), []byte(store.MaskKey(k)))
	}
	return out
}

// RedactText 脱敏一段文本里的 key，用于 URL 与 query string。
//
// 为什么 URL 也要扫：§3.2 提到少数中转站接受 `?key=<key>` 查询参数，
// 而 full_url_mode 的 base_url 正是为这类非标准站准备的 —— 它会被整段
// 存进样本的 out_url。入站 query 同理（客户端可能两处都带）。
// 漏掉这两个字段，§9.4 的「真 key 全表 grep 零命中」就不成立。
//
// URL 里的 key 还有一种**编码**形态：`sk-a/b+c` 在 query 里会写成
// `sk-a%2Fb%2Bc`，直接搜原文搜不到。所以除了原文，还试一次 URL 解码后的
// 匹配 —— 命中就把编码形态一并替换掉。
func RedactText(s string, keys []string) string {
	if s == "" {
		return s
	}
	for _, k := range keys {
		if len(k) < minRedactableKey {
			continue
		}
		masked := store.MaskKey(k)
		s = strings.ReplaceAll(s, k, masked)
		// 编码形态：只在与原文不同时才多做一次替换
		if enc := url.QueryEscape(k); enc != k {
			s = strings.ReplaceAll(s, enc, masked)
		}
		// 少数实现用 PathEscape（不把空格编成 +），也一并覆盖
		if enc := url.PathEscape(k); enc != k {
			s = strings.ReplaceAll(s, enc, masked)
		}
	}
	return s
}

// RedactDiagnostic 脱敏一段要进日志/UI/落库的上游原文。
//
// 与 RedactBodyKeys 的区别只有一条：**不设长度下限**，短 key 也脱敏。
//
// 为什么要两个函数而不是一个：minRedactableKey 那个下限对**样本**是对的 ——
// 样本存的是完整对话原文，一个 4 字符的 key 会在正文里偶然命中无数次，
// 把原文打得千疮百孔，反而毁掉样本的诊断价值。
//
// 但诊断文本（探活的 last_error、转发失败的日志）不同：进来的只是几百字节
// 的错误原文，多打几个码无所谓，而漏一个 key 是实实在在的泄露 —— 它会
// 落进 route_health 表、经 /admin/api/health 显示出来、或者写进日志文件。
// 两种代价不对称，这里就该按「宁可多打码」取舍。
//
// 而短 key 是**真实可达**的配置：config.validate 对 RELAY_KEYS 只校验非空，
// 上游 api_key 同样没有长度下限。
func RedactDiagnostic(body []byte, keys []string) []byte {
	out := RedactBodyKeys(body, keys) // 长 key：保留 MaskKey 的部分可辨形式
	for _, k := range keys {
		// 长 key 已由上面处理，这里只补它按长度跳过的那些。
		//
		// 空 key 显式跳过。当前它其实无害（MaskKey("") 返回空串，于是
		// ReplaceAll 等于原地不动），但那依赖 MaskKey 的实现细节 ——
		// 若它日后改成返回固定掩码，空串替换会在**每个字节之间**插入掩码，
		// 把一段错误原文变成几倍长的乱码。写死这个跳过，不押在别处的行为上。
		if k == "" || len(k) >= minRedactableKey {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(k), []byte(store.MaskKey(k)))
	}
	return out
}

// RedactDiagnosticText 是 RedactDiagnostic 的 string 版本，供拼错误信息用。
func RedactDiagnosticText(s string, keys []string) string {
	if s == "" {
		return s
	}
	return string(RedactDiagnostic([]byte(s), keys))
}

// minRedactableKey 是参与 body 扫描的最短 key 长度。
//
// 太短的字符串在正常 body 里会大量偶然命中（想象一个 4 字符的 key
// 恰好是对话内容的子串），把对话原文打得千疮百孔，反而毁掉样本的诊断价值。
// 真实的 relay key 与上游 key 都远长于此。
//
// 注意这个下限**只对样本适用**。诊断文本走 RedactDiagnostic，它不设下限。
const minRedactableKey = 12
