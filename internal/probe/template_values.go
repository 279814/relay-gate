package probe

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// ErrTemplateValue 表示 Recipe 渲染要的某个值不可用。
//
// 单独一个哨兵：调用方要据此记 config_error 并**不发网络请求**（§8.6 末段），
// 与「上游拒了我们」是完全不同的动作 —— 后者累计健康失败，前者不该影响上游。
var ErrTemplateValue = errors.New("模板值不可用")

// TemplateValues 提供 Recipe 渲染需要的全部内置占位符（§8.5）。
//
// 与 outbound.Values 的分工不是重复：那个只服务 **URL**，刻意只支持
// UPSTREAM_API_KEY 与 SECRET:（见 outbound/target_provider.go 的说明）——
// 模型名与 prompt 属于 body 模板，混进 URL 解析器只会让「谁提供什么」变模糊。
// 本类型服务 Recipe 的 header/query/body 三处，所以要全部六个。
//
// 每次探活现造一个：Secret 与 key 的明文不该常驻在任何长生命周期对象里。
type TemplateValues struct {
	UpstreamAPIKey probetemplate.ResolvedValue
	UpstreamModel  probetemplate.ResolvedValue
	ModelName      probetemplate.ResolvedValue
	ProbePrompt    probetemplate.ResolvedValue
	SessionID      probetemplate.ResolvedValue
	// Timestamp 是这次探活的时刻。零值会被拒绝而不是渲染成 0001-01-01 ——
	// 那是个合法的 RFC3339 串，上游会照收，于是「忘了装配时间」变成一个
	// 发得出去但内容荒谬的请求。
	Timestamp time.Time
	// Secrets 的键是**去掉 SECRET: 前缀**的裸名，与
	// CompiledRecipe.RequiredSecrets() 的返回一致。
	//
	// 装配前必须经 BindSecrets 校验 snapshot ref（§4.5），不能直接从
	// 「按名字查一次库」的结果填进来。
	Secrets map[string]probetemplate.ResolvedValue
}

// timestampLayout 是 TIMESTAMP 的渲染格式。
//
// RFC3339 而不是 Unix 秒：它进的是 body 模板，而上游按 JSON 字段读它。
// 秒级精度足够 —— 更高的精度只会让同一次探活里的两个 TIMESTAMP 占位符
// 渲染出不同的值，而那种不一致没有任何用处。
const timestampLayout = time.RFC3339

// ResolveValue 实现 probetemplate.ValueResolver。
//
// 每个未装配的值都**报错**而不是渲染成空串。空串是最坏的失败方式：
// `"model":""` 会被上游拒绝并回一个含义完全不同的错误（通常是 400 参数
// 错误），于是排查方向从「模型名没传进来」变成「这个站不支持这个模型」。
func (values TemplateValues) ResolveValue(ctx context.Context, name string) (probetemplate.ResolvedValue, error) {
	if secretName, ok := strings.CutPrefix(name, secretPlaceholderPrefix); ok {
		return values.secret(secretName)
	}

	switch name {
	case "UPSTREAM_API_KEY":
		return required(name, values.UpstreamAPIKey)
	case "UPSTREAM_MODEL":
		return required(name, values.UpstreamModel)
	case "MODEL_NAME":
		return required(name, values.ModelName)
	case "PROBE_PROMPT":
		return required(name, values.ProbePrompt)
	case "SESSION_ID":
		return required(name, values.SessionID)
	case "TIMESTAMP":
		if values.Timestamp.IsZero() {
			return probetemplate.ResolvedValue{},
				fmt.Errorf("%w: TIMESTAMP 未装配", ErrTemplateValue)
		}
		// 不带 revision：时间不是配置。给它一个非零值会让配置 hash 每秒都变，
		// 于是 Capability 永远处于「配置变了要重验」。
		return probetemplate.ResolvedValue{
			Plain: []byte(values.Timestamp.UTC().Format(timestampLayout)),
		}, nil
	default:
		// 编译期已有白名单（probetemplate.validatePlaceholder），这里是第二道：
		// 白名单加了新占位符而装配侧忘了跟上时，症状必须是报错而不是渲染成空。
		return probetemplate.ResolvedValue{},
			fmt.Errorf("%w: 不支持的占位符 %q", ErrTemplateValue, name)
	}
}

// secretPlaceholderPrefix 与 probetemplate 的前缀一致，大小写敏感。
const secretPlaceholderPrefix = "SECRET:"

func (values TemplateValues) secret(name string) (probetemplate.ResolvedValue, error) {
	value, ok := values.Secrets[name]
	if !ok {
		// 指名是哪个 Secret，但不带任何明文：这条错误会流进
		// route_health.last_error（落库）并显示在管理界面上。
		return probetemplate.ResolvedValue{},
			fmt.Errorf("%w: Probe Secret %q 未装配", ErrTemplateValue, name)
	}
	return copyValue(value), nil
}

// required 把「装配了没」这个判断收在一处。
func required(name string, value probetemplate.ResolvedValue) (probetemplate.ResolvedValue, error) {
	if len(value.Plain) == 0 {
		return probetemplate.ResolvedValue{},
			fmt.Errorf("%w: %s 未装配", ErrTemplateValue, name)
	}
	return copyValue(value), nil
}

// copyValue 复制明文，不与装配者共享底层数组。
//
// 共享的话，调用方改一个字节就会改掉这份装配好的值，而下一次渲染会用
// 被改过的值 —— 表现为「偶发的认证失败」，且只在同一个 TemplateValues
// 被渲染两次时出现。
func copyValue(value probetemplate.ResolvedValue) probetemplate.ResolvedValue {
	value.Plain = append([]byte(nil), value.Plain...)
	return value
}

// BindSecrets 校验解析出的 Secret 与 Recipe 版本的 snapshot ref 一致，
// 通过后才降为普通 ResolvedValue（§4.5）。
//
// 为什么这是安全边界而不是洁癖：删掉一个 Secret 再建一个同名的，拿到的是
// **不同的 ID**。若按名字匹配就放行，那个 Recipe 会静默改用一份没人为它
// 审核过的凭据 —— 而它发出去的请求看起来完全正常。规格的原话是
// 「同名新 Secret 绝不自动满足旧 ref」。
//
// 缺失与多余都拒绝。多余同样是错的：模板没引用的 Secret 出现在装配里，
// 说明 ref 清单与实际编译出的模板不是同一份，而那意味着其中一份已过期。
func BindSecrets(refs []model.RequiredSecretRef,
	resolved map[string]probetemplate.ResolvedSecret) (map[string]probetemplate.ResolvedValue, error) {

	bound := make(map[string]probetemplate.ResolvedValue, len(refs))
	for _, ref := range refs {
		secret, ok := resolved[ref.Name]
		if !ok {
			return nil, fmt.Errorf("%w: Recipe 引用的 Probe Secret %q 未解析",
				ErrTemplateValue, ref.Name)
		}
		if secret.ID != ref.BoundSecretID {
			// 不带明文，也不带两个 ID 之外的任何信息。
			return nil, fmt.Errorf("%w: Probe Secret %q 的 secret_id 已变（绑定 %d，当前 %d）；"+
				"同名新建的 Secret 不会自动满足旧引用，请重新测试并发布",
				ErrTemplateValue, ref.Name, ref.BoundSecretID, secret.ID)
		}
		bound[ref.Name] = probetemplate.ResolvedValue{
			Plain:    append([]byte(nil), secret.Plain...),
			Revision: secret.Revision,
		}
	}
	if len(resolved) != len(bound) {
		for name := range resolved {
			if _, ok := bound[name]; !ok {
				return nil, fmt.Errorf("%w: 解析出模板未引用的 Probe Secret %q，"+
					"引用清单与模板不同源", ErrTemplateValue, name)
			}
		}
	}
	return bound, nil
}
