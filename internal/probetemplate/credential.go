package probetemplate

import (
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

// 凭据门禁（§4.5）。三条写入路径（管理 API、learner、migration）都经
// ScanRequiredSecrets 入库，所以门禁放在这里就覆盖了全部三条。
//
// 要挡的是什么：一个 Recipe 能把 `Authorization: sk-ant-xxx` 明文存进
// probe_recipe_version，而那张表是**不可变**的（0002 的 no_update/no_delete
// 触发器）—— 明文一旦落进去就删不掉，只能整行留着。而 Upstream 的 api_key
// 是加密存的，让 Recipe 开一个明文旁路等于把加密存储整个绕过去。
//
// 判据只有两条，刻意保守。规格明说「不提供跳过扫描开关」，也就是说误报
// **没有逃生舱** —— 一个把正常模板判成凭据的扫描器会让用户无法保存合法配置，
// 而那比漏检更难绕过。所以宁可漏掉低置信的形状，也不猜。

// credentialPrefixes 是高置信的凭据前缀。
//
// 只收「厂商明确定义、几乎不可能出现在正常提示词里」的那几个。像 "key-"
// 或纯高熵串这类不收：前者是常见英文词，后者与 base64 图片、hash、
// minified JS 无法区分 —— 而 base64 图片正是探活 body 里可能出现的东西。
var credentialPrefixes = []string{
	"sk-ant-",   // Anthropic
	"sk-proj-",  // OpenAI 项目密钥
	"sk-or-v1-", // OpenRouter
	"ghp_",      // GitHub personal access token
	"gho_",      // GitHub OAuth
	"github_pat_",
	"xoxb-", // Slack bot
	"xoxp-", // Slack user
	"AKIA",  // AWS access key ID
	"ASIA",  // AWS 临时凭据
}

// minLiteralAuthValue 是认证头里「像凭据」的最短字面值长度。
//
// 认证头的值只有两种正当形态：占位符，或占位符加一个 scheme 前缀。
// 短字面值（如 "Basic"、"none"）多半是协议常量而不是凭据，
// 而 16 字符以上的不透明串在认证头里基本只能是 key 本身。
const minLiteralAuthValue = 16

// authSchemes 是认证头里允许剥掉的 scheme 前缀。
//
// `Bearer {{UPSTREAM_API_KEY}}` 是规格推荐的写法，所以要能剥掉 scheme
// 再看后面剩下什么 —— 只看「有没有 Bearer」会让 `Bearer sk-xxx` 也放行。
//
// 只收这两个：ApplyAuth 实际会写的是 Bearer（outbound/auth.go），
// Basic 在中转站上没见过但剥掉它总是对的。不预先收 Token / ApiKey
// 这类没见过的 scheme —— 多收一个就多一条「scheme 后面的字面值被放行」
// 的路径，而收窄的代价只是用户把它写成占位符。
var authSchemes = []string{"bearer", "basic"}

// rejectLiteralCredentials 是入库前的凭据门禁。
//
// 对认证头用「必须是占位符」这条强规则，对其余位置只查高置信前缀：
// 认证头的值本来就只该是凭据，所以「不是占位符」即可判定；而 body 与 query
// 里绝大多数内容是正常载荷，只能靠明确的前缀。
func rejectLiteralCredentials(content TemplateContent) error {
	for _, header := range content.Headers {
		for _, value := range header.Values {
			if model.IsAuthHeader(header.Name) {
				if err := requirePlaceholderAuthValue(header.Name, value); err != nil {
					return err
				}
				continue
			}
			if err := rejectCredentialPrefix(value, "header "+header.Name); err != nil {
				return err
			}
		}
	}
	if err := rejectCredentialPrefix(content.RawQuery, "固定 query"); err != nil {
		return err
	}
	return rejectCredentialPrefix(string(content.Body), "body 模板")
}

// requirePlaceholderAuthValue 要求认证头的值由占位符提供。
//
// 错误信息给出**该怎么改**：规格要求误报由「用户创建 Probe Secret 后改成
// 占位符」解决，而一句「不允许」不告诉用户往哪走。
func requirePlaceholderAuthValue(name, value string) error {
	remainder := strings.TrimSpace(value)
	// 剥掉一个允许的 scheme 前缀再看剩下什么。
	if index := strings.IndexByte(remainder, ' '); index > 0 {
		scheme := strings.ToLower(remainder[:index])
		for _, allowed := range authSchemes {
			if scheme == allowed {
				remainder = strings.TrimSpace(remainder[index+1:])
				break
			}
		}
	}
	if remainder == "" {
		return nil
	}
	// 整体是一个占位符就放行。要求「整体」而不是「含有」：
	// `sk-live-{{SECRET:suffix}}` 那种拼法里前半段仍是明文凭据。
	if strings.HasPrefix(remainder, "{{") && strings.HasSuffix(remainder, "}}") &&
		strings.Count(remainder, "{{") == 1 {
		return nil
	}
	if len(remainder) < minLiteralAuthValue {
		// 短字面值放行：多半是协议常量。这里刻意留松 —— 见文件头
		// 「误报没有逃生舱」。高置信前缀仍会被下面那条兜住。
		return rejectCredentialPrefix(value, "认证头 "+name)
	}
	return model.WrapValidation("认证头 %q 不能写字面凭据，"+
		"请改用 {{UPSTREAM_API_KEY}} 或先创建 Probe Secret 再写 {{SECRET:name}}（§4.5）", name)
}

// rejectCredentialPrefix 查高置信凭据前缀。
//
// 错误里**只报前缀**，绝不回显命中的原值：这条错误会进 API 响应与日志，
// 而回显等于把刚被拒绝的凭据又抄了一份到日志里。
func rejectCredentialPrefix(value, where string) error {
	for _, prefix := range credentialPrefixes {
		if !strings.Contains(value, prefix) {
			continue
		}
		// 前缀后面得真有内容才算凭据，否则 "怎么用 sk-ant- 开头的 key"
		// 这类正常提问会被判成凭据。
		if !hasOpaqueTailAfter(value, prefix) {
			continue
		}
		return model.WrapValidation("%s 含以 %q 开头的字面凭据，"+
			"请改用 {{UPSTREAM_API_KEY}} 或 {{SECRET:name}} 占位符（§4.5）", where, prefix)
	}
	return nil
}

// hasOpaqueTailAfter 判断前缀后面是否跟着一段够长的不透明串。
//
// AWS 的 AKIA 没有分隔符，长度固定 20；其余带 - 或 _ 的前缀后面是变长的
// base62。取 12 作为门槛：真实 key 远长于此，而正常散文里提到
// "sk-ant-" 时后面通常是空格、标点或换行。
func hasOpaqueTailAfter(value, prefix string) bool {
	const minOpaqueTail = 12
	for offset := 0; ; {
		index := strings.Index(value[offset:], prefix)
		if index < 0 {
			return false
		}
		tail := value[offset+index+len(prefix):]
		length := 0
		for length < len(tail) && isOpaqueByte(tail[length]) {
			length++
		}
		if length >= minOpaqueTail {
			return true
		}
		offset += index + len(prefix)
	}
}

func isOpaqueByte(character byte) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') ||
		character == '-' || character == '_'
}
