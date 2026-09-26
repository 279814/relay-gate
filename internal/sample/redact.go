// Package sample 记录每次转发的三份内容 + 四个时间戳（§3.6）。
//
// 全包的设计前提是**旁路**：记录失败、记录变慢、记录被丢弃，都绝不能影响转发。
// 宁可丢样本，也不让「记日志」拖慢或拖垮转发 —— 这是主次关系，不能倒置。
package sample

import (
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
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
		// 管理口令：若误带到 /v1 样本入站头，值绝不能明文落库。
		"X-Admin-Password": true,
	}
	for _, h := range model.AuthHeaders {
		m[http.CanonicalHeaderKey(h)] = true
	}
	return m
}()

// IsSensitiveHeader 判断一个头名是否携带凭据（大小写不敏感）。
//
// 导出它是为了让「从样本导出探活头模板」（§3.6.4）复用同一份清单。
// 那边各抄一份的后果与本文件开头说的一样：新增一个凭据位置时漏掉同步，
// 而漏掉的表现是一个**脱敏后的假凭据**被写进 probe_headers ——
// 它会覆盖真实鉴权头，把整站探活打成 401，且界面显示「鉴权失败」，
// 排查方向完全指错（去查真 key 对不对）。
//
// 这份清单本身仍以 sensitiveHeaders 为唯一来源，它由 model.AuthHeaders 派生。
func IsSensitiveHeader(name string) bool {
	return sensitiveHeaders[http.CanonicalHeaderKey(strings.TrimSpace(name))]
}

// RedactHeaders 返回脱敏后的头副本。原 header 不被修改 ——
// 它可能还在被转发路径读，改它就违反了「绝不影响转发」。
//
// keys 是已知 Secret（上游 key、relay key、transform secret_ref 渲染值）。
// 敏感头名整值打码；非敏感头仍要扫 keys（§5.4：请求头扫描已知 Secret）——
// request transform 可把 upstream key 写进 X-Custom 之类的非认证头，
// 只靠头名清单会把明文留进样本，管理员解密后仍能看见。
func RedactHeaders(h http.Header, keys []string) http.Header {
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
				cp[i] = RedactText(v, keys)
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
// 与 finding Detail / RedactDiagnostic 共用 security.RedactSecrets：原文、
// url.QueryEscape、小写 hex 百分号编码、以及 JSON \uXXXX（hex 大小写不敏感）
// 一并遮掉。不能只做原文 ReplaceAll，否则编码形态会漏进落库样本
// （PrepareBody → recordSample 的 in/out body）。
//
// 没命中时返回原 slice，不做拷贝：绝大多数样本不含 key（§3.6.3a
// 要求采集不拖慢转发）。命中时才 string → RedactSecrets → []byte。
func RedactBodyKeys(body []byte, keys []string) []byte {
	if len(body) == 0 {
		return body
	}
	var any bool
	for _, k := range keys {
		if len(k) >= model.MinRedactableKeyLen {
			any = true
			break
		}
	}
	if !any {
		return body
	}
	s := string(body)
	out := security.RedactSecrets(s, keys)
	if out == s {
		return body
	}
	return []byte(out)
}

// RedactText 脱敏一段文本里的 key，用于 URL、query string 与非认证头值。
//
// 为什么 URL 也要扫：少数中转站接受 `?key=<key>` 查询参数，由
// FixedQueryTemplate / legacy_exact 表达（§7.1；base_url 本身不允许 query，
// §5.1）—— 出站 URL 会被整段存进样本的 out_url。入站 query 同理
// （客户端可能两处都带）。非认证头（X-Custom / Referer 等）同理：
// transform 或回显可能只留下编码形态。
// 漏掉这些字段，§9.4 的「真 key 全表 grep 零命中」就不成立。
//
// 与 finding Detail / RedactBodyKeys / RedactDiagnostic 共用
// security.RedactSecrets：原文、url.QueryEscape、小写 hex 百分号编码、
// 以及 JSON \uXXXX（hex 大小写不敏感）一并遮掉。不能只做原文
// ReplaceAll，否则编码形态会漏进落库样本头 / out_url / in_query。
// 短于 MinRedactableKeyLen 的 needle 由 RedactSecrets 跳过。
// 只改落库副本；live RoundTrip 头图不经此路径。
func RedactText(s string, keys []string) string {
	if s == "" {
		return s
	}
	return security.RedactSecrets(s, keys)
}

// urlCarryingResponseHeaders 是响应里可能携带完整 URL 的头。
// 上游若把出站请求 URL（含 FixedQueryTemplate / legacy_exact 里的 key）
// 回显到这些头，原样透传就把上游 key 交给了外部客户端。
// Link 的 URL 在尖括号内；RedactText 只替凭据子串，rel= 等参数不动。
var urlCarryingResponseHeaders = []string{
	"Location",
	"Content-Location",
	"Refresh",
	"Link",
}

// RedactCredentialURLHeaders 就地脱敏响应头里 URL 携带的已知 Secret。
//
// 只用 RedactText：只替凭据值，不动状态码、路径与无关 query（如 beta=true）。
// keys 为空时是空操作。原 header 可能已经抄进 ResponseWriter，必须原地改。
func RedactCredentialURLHeaders(h http.Header, keys []string) {
	if h == nil || len(keys) == 0 {
		return
	}
	for _, name := range urlCarryingResponseHeaders {
		vals := h.Values(name)
		if len(vals) == 0 {
			continue
		}
		h.Del(name)
		for _, v := range vals {
			h.Add(name, RedactText(v, keys))
		}
	}
}

// RedactDiagnostic 脱敏一段要进日志/UI/落库的上游原文。
//
// 与 finding Detail / RedactDiagnosticText 共用 security.RedactSecrets：原文、
// url.QueryEscape、小写 hex 百分号编码、以及 JSON \uXXXX（hex 大小写不敏感）
// 一并遮掉。不能只做原文 ReplaceAll，否则编码形态会漏进 ErrBody / last_error /
// count_tokens 日志。
//
// 与 RedactBodyKeys / RedactText 一样跳过短于 MinRedactableKeyLen 的 needle
// （含空串）：把 "api"/"key"/"" 当 ReplaceAll 目标会把 URL 与错误原文打坏。
// 写入路径已拒绝短上游 api_key；脏行/历史短钥由出站 fail-closed 挡住，
// 这里不再用短串做子串替换。
func RedactDiagnostic(body []byte, keys []string) []byte {
	if len(body) == 0 {
		return body
	}
	return []byte(security.RedactSecrets(string(body), keys))
}

// RedactDiagnosticText 脱敏拼进错误信息 / 请求日志的文本。
//
// 与 finding Detail / RedactDiagnostic 共用 security.RedactSecrets：原文、
// url.QueryEscape、小写 hex 百分号编码、以及 JSON \uXXXX（hex 大小写不敏感）
// 一并遮掉。短于 MinRedactableKeyLen 的 needle（含空串）同样跳过。
func RedactDiagnosticText(s string, keys []string) string {
	if s == "" {
		return s
	}
	return security.RedactSecrets(s, keys)
}
