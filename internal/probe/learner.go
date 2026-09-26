package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
	"github.com/279814/relay-gate/internal/sample"
)

// gatewaySessionCookieName 与 proxy/api 的 relay_session 同名。
//
// 学习器绝不能把管理会话 Cookie 写进 profile：那是本进程凭据，不是上游指纹。
// 这里再钉一次名字，避免只依赖 sample.IsSensitiveHeader 的 Cookie 整头丢弃时
// 有人改清单漏掉「只剥会话名」这条语义。
const gatewaySessionCookieName = "relay_session"

// Learner 把已脱敏的 ClientRequestShape 收成 candidate profile。
type Learner struct {
	mu        sync.Mutex
	byShape   map[string]*model.ClientProbeProfile
	perScope  map[string]int
	global    int
	maxScope  int
	maxGlobal int
	store     LearnerStore
}

// LearnerStore 持久化 candidate（可选）。
type LearnerStore interface {
	UpsertClientProbeProfile(ctx context.Context, profile *model.ClientProbeProfile) error
}

// NewLearner 构造有界 Learner。
func NewLearner(store LearnerStore) *Learner {
	return &Learner{
		byShape:   map[string]*model.ClientProbeProfile{},
		perScope:  map[string]int{},
		maxScope:  32,
		maxGlobal: 256,
		store:     store,
	}
}

// ObserveSuccessful 只接收正常成功与已 sanitizer 的 shape。
//
// §8.4：不得保存认证值。入站 shape 仍可能带 Authorization / X-Api-Key /
// Api-Key、Cookie 里的 relay_session、或纯凭据 query —— 在入库前再剥一层，
// 不信任上游 sanitizer 已做完。安全协议头（如 anthropic-beta）保留。
func (l *Learner) ObserveSuccessful(ctx context.Context, upstreamID int64, endpoint model.EndpointKind, shape model.ClientRequestShape) error {
	if l == nil {
		return nil
	}
	shape = sanitizeLearnedShape(endpoint, shape)
	hash := ShapeHash(shape)
	if hash == "" {
		return nil
	}
	scope := fmt.Sprintf("%d:%s", upstreamID, endpoint)
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, ok := l.byShape[hash]; ok {
		existing.SeenCount++
		return nil
	}
	if l.perScope[scope] >= l.maxScope || l.global >= l.maxGlobal {
		return nil
	}
	profile := &model.ClientProbeProfile{
		UpstreamID:     upstreamID,
		Endpoint:       endpoint,
		Status:         model.ProfileCandidate,
		SafeHeaders:    shape.SafeHeaders,
		FixedRawQuery:  shape.FixedRawQuery,
		QueryShapeJSON: append([]byte(nil), shape.QueryShapeJSON...),
		BodyTemplate:   append([]byte(nil), shape.BodyTemplate...),
		BodyShapeJSON:  append([]byte(nil), shape.BodyShapeJSON...),
		ShapeHash:      hash,
		Revision:       1,
		SeenCount:      1,
	}
	l.byShape[hash] = profile
	l.perScope[scope]++
	l.global++
	if l.store != nil {
		return l.store.UpsertClientProbeProfile(ctx, profile)
	}
	return nil
}

// sanitizeLearnedShape 丢掉凭据类字段，只留下可学习的安全形状（§8.4）。
//
// BodyTemplate 不信任入站字节：真实请求 body 可能含 messages/system/tools
// 与认证值。探活用的 body 一律物化成该端点的紧凑探活体（占位符 + 文档
// 允许的标志），绝不 JSON 往返客户端原文。BodyShapeJSON 仍只作类型图保管。
//
// 不记录被丢掉的值 —— 那正是凭据，进日志等于泄露。
func sanitizeLearnedShape(endpoint model.EndpointKind, shape model.ClientRequestShape) model.ClientRequestShape {
	return model.ClientRequestShape{
		SafeHeaders:    filterLearnedHeaders(shape.SafeHeaders),
		FixedRawQuery:  filterLearnedQuery(shape.FixedRawQuery),
		QueryShapeJSON: shape.QueryShapeJSON,
		BodyTemplate:   materializeLearnedBodyTemplate(endpoint),
		BodyShapeJSON:  shape.BodyShapeJSON,
	}
}

// materializeLearnedBodyTemplate 生成该端点的紧凑探活 body（§8.4）。
//
// 与内置 compact 模板同形：model / 输出上限 / stream（若适用）+ 单条
// {{PROBE_PROMPT}}，不含 system、tools、metadata、客户端 messages 原文或
// 认证值。入站 BodyTemplate 一律忽略，避免把真实流量 JSON 拷进探活。
func materializeLearnedBodyTemplate(endpoint model.EndpointKind) []byte {
	switch endpoint {
	case model.EndpointModels:
		return nil
	case model.EndpointMessages:
		return []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"{{PROBE_PROMPT}}"}]}]}`)
	case model.EndpointCountTokens:
		return []byte(`{"model":"{{UPSTREAM_MODEL}}","messages":[{"role":"user","content":[{"type":"text","text":"{{PROBE_PROMPT}}"}]}]}`)
	case model.EndpointChatCompletions:
		return []byte(`{"model":"{{UPSTREAM_MODEL}}","messages":[{"role":"user","content":"{{PROBE_PROMPT}}"}],"max_tokens":1,"stream":true}`)
	case model.EndpointResponses:
		return []byte(`{"model":"{{UPSTREAM_MODEL}}","input":[{"role":"user","content":[{"type":"input_text","text":"{{PROBE_PROMPT}}"}]}],"max_output_tokens":16,"stream":true}`)
	default:
		return nil
	}
}

// filterLearnedHeaders 排除认证头与 Cookie（含 relay_session），并对非认证头
// 的值跑与 recipe 入库相同的高置信凭据前缀门禁（rejectLiteralCredentials /
// rejectCredentialPrefix）。头名不是 AuthHeaders 仍可能把 sk-ant-… 写进
// SafeHeaders；query 路径已有同类扫描，头不能留旁路。占位符与协议常量保留。
//
// 清单复用 sample.IsSensitiveHeader（由 model.AuthHeaders 派生，另含 Cookie /
// Proxy-Authorization），与样本导出探活头同一道门 —— 两处各抄一份会分叉。
func filterLearnedHeaders(headers []model.HeaderTemplate) []model.HeaderTemplate {
	if len(headers) == 0 {
		return nil
	}
	out := make([]model.HeaderTemplate, 0, len(headers))
	for _, header := range headers {
		if sample.IsSensitiveHeader(header.Name) {
			continue
		}
		if cookieValuesContainGatewaySession(header) {
			continue
		}
		kept := filterLearnedHeaderValues(header.Values)
		if len(kept) == 0 {
			continue
		}
		out = append(out, model.HeaderTemplate{
			Name:   header.Name,
			Values: kept,
		})
	}
	return out
}

// filterLearnedHeaderValues 丢掉命中高置信凭据前缀的值；占位符与普通常量保留。
func filterLearnedHeaderValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if learnedHeaderValueHasLiteralCredential(value) {
			continue
		}
		kept = append(kept, value)
	}
	return kept
}

// learnedHeaderValueHasLiteralCredential 复用 recipe 凭据门禁判字面 key。
//
// 用非认证头名走 ScanRequiredSecrets，只触发 rejectCredentialPrefix（§8.5），
// 不走认证头「必须是占位符」那条，也不用 RejectLiteralAuthFieldValue。
// 与 filterLearnedQuery 相反：头里的 {{UPSTREAM_API_KEY}} / {{SECRET:name}}
// 是合法指纹，必须保留。
func learnedHeaderValueHasLiteralCredential(value string) bool {
	_, err := probetemplate.ScanRequiredSecrets(model.EndpointModels, probetemplate.TemplateContent{
		Method: "GET",
		Headers: []model.HeaderTemplate{
			{Name: "X-Learned", Values: []string{value}},
		},
	})
	return err != nil
}

// cookieValuesContainGatewaySession 是纵深防御：IsSensitiveHeader 已整头丢
// Cookie，若将来清单漏掉 Cookie，仍不能让 relay_session 进 profile。
func cookieValuesContainGatewaySession(header model.HeaderTemplate) bool {
	if !strings.EqualFold(strings.TrimSpace(header.Name), "Cookie") {
		return false
	}
	for _, line := range header.Values {
		for _, part := range strings.Split(line, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if strings.TrimSpace(name) == gatewaySessionCookieName {
				return true
			}
		}
	}
	return false
}

// filterLearnedQuery 丢掉「值整段就是凭据」的 query 参数。
//
// 保序、不重编码：形状哈希依赖 FixedRawQuery 的字节稳定。只删段，不改其余段。
func filterLearnedQuery(raw string) string {
	if raw == "" {
		return ""
	}
	segments := strings.Split(raw, "&")
	kept := make([]string, 0, len(segments))
	for _, segment := range segments {
		value := ""
		hasEquals := false
		if separator := strings.IndexByte(segment, '='); separator >= 0 {
			value, hasEquals = segment[separator+1:], true
		}
		if hasEquals && isSecretOnlyQueryValue(value) {
			continue
		}
		kept = append(kept, segment)
	}
	return strings.Join(kept, "&")
}

// isSecretOnlyQueryValue 判断 query 值是不是整段凭据（占位符或字面 key）。
//
// 字面 key 复用 recipe 凭据门禁：与入库扫描同一判据，避免学习器放行而
// Upsert 再拒（或反过来）。错误文本不回显 value。
func isSecretOnlyQueryValue(value string) bool {
	decoded := value
	if unescaped, err := url.QueryUnescape(value); err == nil {
		decoded = unescaped
	}
	decoded = strings.TrimSpace(decoded)
	if decoded == "" {
		return false
	}
	if decoded == "{{UPSTREAM_API_KEY}}" {
		return true
	}
	if strings.HasPrefix(decoded, "{{SECRET:") && strings.HasSuffix(decoded, "}}") &&
		strings.Count(decoded, "{{") == 1 {
		return true
	}
	_, err := probetemplate.ScanRequiredSecrets(model.EndpointModels, probetemplate.TemplateContent{
		Method:   "GET",
		RawQuery: "x=" + value,
	})
	return err != nil
}

// ShapeHash 对排序规范化后的安全 shape 做带域 SHA-256。
func ShapeHash(shape model.ClientRequestShape) string {
	h := sha256.New()
	_, _ = h.Write([]byte("relay-gate:client-shape:v1\n"))
	_, _ = h.Write([]byte(shape.FixedRawQuery))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(shape.QueryShapeJSON)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(shape.BodyShapeJSON)
	_, _ = h.Write([]byte{0})
	for _, hdr := range shape.SafeHeaders {
		_, _ = h.Write([]byte(hdr.Name))
		_, _ = h.Write([]byte{0})
		for _, v := range hdr.Values {
			_, _ = h.Write([]byte(v))
			_, _ = h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ForgetUpstream drops in-memory learned shapes for one Upstream (§9.2).
func (l *Learner) ForgetUpstream(upstreamID int64) {
	if l == nil || upstreamID <= 0 {
		return
	}
	prefix := fmt.Sprintf("%d:", upstreamID)
	l.mu.Lock()
	defer l.mu.Unlock()
	for hash, profile := range l.byShape {
		if profile != nil && profile.UpstreamID == upstreamID {
			delete(l.byShape, hash)
			l.global--
		}
	}
	for scope := range l.perScope {
		if len(scope) >= len(prefix) && scope[:len(prefix)] == prefix {
			l.global -= l.perScope[scope]
			if l.global < 0 {
				l.global = 0
			}
			delete(l.perScope, scope)
		}
	}
}
