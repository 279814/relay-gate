package probetemplate

import (
	"fmt"
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

// RejectLiteralAuthFieldValue 拒绝认证字段里的纯字面凭据（§7.2 / §8.5）。
//
// 用于 endpoint manual_headers 与探活自定义认证：这些头名故意不是
// model.AuthHeaders（manual 不得写标准别名），所以 rejectLiteralCredentials
// 对它们只跑高置信前缀 —— `sk-live-…` 这类非厂商前缀会漏网。本函数补上
// 「无占位符的长字面值」那条。含 {{UPSTREAM_API_KEY}} / {{SECRET:name}} 的
// 写法（含 `tok {{UPSTREAM_API_KEY}}` 这类前缀拼法）仍放行；短结构常量
// （如租户名）放行，除非命中高置信前缀。
func RejectLiteralAuthFieldValue(value string) error {
	remainder := strings.TrimSpace(value)
	if remainder == "" {
		return nil
	}
	_, placeholders, err := splitAuthValue(remainder)
	if err != nil {
		// 编译不过的值交给后面的正式编译报错。
		return nil
	}
	if placeholders >= 1 {
		return nil
	}
	if len(remainder) < minLiteralAuthValue {
		return rejectCredentialPrefix(value, "认证字段")
	}
	return model.WrapValidation("认证字段不能写字面凭据，"+
		"请改用 {{UPSTREAM_API_KEY}} 或先创建 Probe Secret 再写 {{SECRET:name}}（§4.5）")
}

// rejectLiteralCredentials 是入库前的凭据门禁。
//
// 对认证头用「必须是占位符」这条强规则，对其余位置只查高置信前缀：
// 认证头的值本来就只该是凭据，所以「不是占位符」即可判定；而 body 与 query
// 里绝大多数内容是正常载荷，只能靠明确的前缀。
//
// 位置标识用序号而不是 header 名：本函数跑在 validHeaderName **之前**
// （compileContent 先调门禁再逐个校验 header），所以这里的 header.Name 是
// 未经校验的原始输入 —— 一份被误配成 header 名的 key 会随错误进日志。
// 认证头是唯一的例外，见 authHeaderLabel。
func rejectLiteralCredentials(content TemplateContent) error {
	for index, header := range content.Headers {
		for _, value := range header.Values {
			if model.IsAuthHeader(header.Name) {
				if err := requirePlaceholderAuthValue(header.Name, value); err != nil {
					return err
				}
				continue
			}
			if err := rejectCredentialPrefix(value, fmt.Sprintf("第 %d 个 header 的值", index+1)); err != nil {
				return err
			}
		}
	}
	if err := rejectCredentialPrefix(content.RawQuery, "固定 query"); err != nil {
		return err
	}
	return rejectCredentialPrefix(string(content.Body), "body 模板")
}

// authHeaderLabel 给出认证头在错误里的名字。
//
// 这一处**刻意回显**，与 rejectLiteralCredentials 的其余位置相反：能走到这里
// 说明 model.IsAuthHeader 已经匹配上了，也就是说这个名字来自
// model.AuthHeaders 那份固定清单，是常量而不是游散输入。而这条错误的全部价值
// 就是告诉用户「哪个认证头要改成占位符」—— 配了多个头的用户否则不知道改哪个。
//
// 大小写按清单里的规范写法输出，不用用户传进来的那份：`AUTHORIZATION` 与
// `authorization` 都会匹配，而错误里出现用户的大小写变体等于回显了输入的一部分。
func authHeaderLabel(name string) string {
	for _, known := range model.AuthHeaders {
		if strings.EqualFold(known, strings.TrimSpace(name)) {
			return known
		}
	}
	return "认证头"
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
	//
	// 问编译器而不是看字符串形状。曾用
	// HasPrefix("{{") && HasSuffix("}}") && Count("{{")==1 判「整体」，
	// 而 `{{UPSTREAM_API_KEY}}sk-ant-AAAA}}` 三条全中却含明文凭据 ——
	// 形状判据永远会有下一个这样的构造，而 compileTemplate 已经把值精确切成
	// literal / placeholder 两类，「除占位符外还剩别的」是它能直接回答的问题。
	literal, placeholders, err := splitAuthValue(remainder)
	if err != nil {
		// 编译不过的值（未闭合占位符、未知占位符）交给后面的正式编译报错 ——
		// 那里的错误信息更准确。这里只负责「编译得过但含明文凭据」。
		return nil
	}
	if literal == "" && placeholders == 1 {
		return nil
	}
	if placeholders == 0 && len(remainder) < minLiteralAuthValue {
		// 短纯字面值放行：多半是协议常量。这里刻意留松 —— 见文件头
		// 「误报没有逃生舱」。高置信前缀仍会被下面那条兜住。
		return rejectCredentialPrefix(value, "认证头 "+authHeaderLabel(name))
	}
	return model.WrapValidation("认证头 %s 不能写字面凭据，"+
		"请改用 {{UPSTREAM_API_KEY}} 或先创建 Probe Secret 再写 {{SECRET:name}}（§4.5）",
		authHeaderLabel(name))
}

// splitAuthValue 把认证头的值切成「字面部分」与「占位符个数」。
//
// 复用 compileTemplate 而不是重写一个解析器：转义规则（`{{{{` → `{{`）
// 与占位符白名单都在它那里，各写一份必然分叉 —— 而分叉的那一半正是旁路。
//
// required 收集的 Secret 名在这里丢掉：本函数只用于门禁判断，
// 真正的 requiredSecrets 由 compileContent 那次编译产出。
func splitAuthValue(value string) (literal string, placeholders int, err error) {
	parts, err := compileTemplate([]byte(value), false, make(map[string]struct{}))
	if err != nil {
		return "", 0, err
	}
	var builder strings.Builder
	for _, part := range parts {
		if part.placeholder != "" {
			placeholders++
			continue
		}
		builder.Write(part.literal)
	}
	return strings.TrimSpace(builder.String()), placeholders, nil
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
