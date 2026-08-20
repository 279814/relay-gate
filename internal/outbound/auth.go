package outbound

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// ErrAuthConfig 表示认证 profile 配错了或凭据不可用。
//
// 单独一个哨兵：调用方要据此把 Capability 记成 config_error 并**不发网络请求**
// （§6.5 的 route-local 失败），与「上游拒了我们的认证」是完全不同的动作 ——
// 后者要累计健康失败，前者不该影响上游健康。
var ErrAuthConfig = errors.New("认证配置不可用")

// AuthInput 是一次认证改写的输入。
type AuthInput struct {
	Profile model.EndpointAuthProfile
	Values  ValueResolver
	// Use 区分真实流量与合成探活。零值按真实流量处理 —— 那是绝大多数调用，
	// 而探活侧只有一处，显式给出即可。
	Use ResolveUse
}

// ApplyAuth 是**唯一**的出站认证改写器（§7.2）。
//
// 存在的理由：转发路径的 injectAuth 与探活路径的 injectAuth 原先是两份代码，
// 而「探活用一种认证、真实请求用另一种」的故障表现为「探活说站活着，
// 但用户一直 401」—— 极难定位，因为两条路径各自看起来都对。
//
// 三条不变量，顺序也是不变量的一部分：
//
//  1. **先删所有入站认证别名**（model.AuthHeaders 全部），再写上游认证。
//     漏删任何一个就是把用户的 relay key 直接送给公益站，而它不报错、
//     不失败，只有抓包才能发现。删除动作在**任何**返回路径之前完成，
//     包括失败路径 —— header 是共享的可变对象，半途返回时残留的
//     relay key 仍会随请求发出去。
//
//  2. **最终只写一种 profile**。同时发多种认证是在猜，而严格校验的站会
//     因此拒绝请求（§7.2 明确禁止无依据地同时发送多个认证头）。
//     唯一的例外是 legacy_auto_real_only，它有历史依据：这个站在 schema 1
//     时代就是双发且能用。
//
//  3. **渲染之后再校验一次最终 header**。渲染前的模板是干净的（写入时校验过），
//     脏字节来自 Secret 值 —— 而 CR/LF 就是请求头注入的实现手段。
//     校验必须在写 socket **之前**，也就是这次尝试完全不出网。
func ApplyAuth(ctx context.Context, header http.Header, in AuthInput) error {
	if header == nil {
		return fmt.Errorf("%w: 缺少出站请求头", ErrAuthConfig)
	}

	// 不变量 1：先删，且在任何 return 之前。
	for _, name := range model.AuthHeaders {
		header.Del(name)
	}

	written, err := applyAuthMode(ctx, header, in)
	if err != nil {
		return err
	}
	// 不变量 3：统一在出口验一次 ApplyAuth 自己写进去的每个值。
	//
	// 放在一个出口而不是每条分支各验一次：分支有六条，漏掉任何一条就是一个
	// 注入口，而漏没漏只能靠人去核对。写进去之后再验则天然覆盖全部分支，
	// 包括将来新增的。
	//
	// 校验失败时把已写的头删掉：调用方拿到错误后若继续发（不该，但 header
	// 是共享的可变对象），发出去的会是一个带注入内容的请求。
	for _, name := range written {
		for _, value := range header.Values(name) {
			if err := validateHeaderCredential([]byte(value)); err != nil {
				for _, dirty := range written {
					header.Del(dirty)
				}
				return fmt.Errorf("%w: 出站认证头 %q %v", ErrAuthConfig, name, err)
			}
		}
	}
	return nil
}

// applyAuthMode 按 profile 写认证头，返回它写过的头名。
//
// 返回头名而不是让调用方猜：出口校验要精确知道「哪些头是 ApplyAuth 写的」，
// 按 AuthHeaders 全表扫会漏掉 manual 模式的自定义头名。
func applyAuthMode(ctx context.Context, header http.Header, in AuthInput) ([]string, error) {
	if !in.Profile.Mode.Valid() {
		return nil, fmt.Errorf("%w: auth mode 无效 %q", ErrAuthConfig, in.Profile.Mode)
	}

	mode := in.Profile.Mode
	if mode == model.AuthModeAutoCalibrated {
		if !in.Profile.CalibratedMode.Valid() {
			// 校准过的 profile 才知道该发哪一种。没校准就猜，等于把
			// 「还不知道」当成「知道了」—— 而猜错的代价是把一个好站探成死站。
			return nil, fmt.Errorf("%w: auth profile 尚未校准，请先运行一次校准", ErrAuthConfig)
		}
		mode = in.Profile.CalibratedMode
	}

	switch mode {
	case model.AuthModeFixedQuery:
		// key 在 query 里的站：一个头都不写。
		// query 侧由 EndpointResolver 的 FixedQueryTemplate 提供，而它必须是
		// **显式**的 —— 只声明「key 在 query 里」却没说在哪个参数里，
		// 唯一安全的动作是 config_error：猜一个参数名会让 key 根本没送到，
		// 而请求看起来完全正常。
		if strings.TrimSpace(in.Profile.QueryName) == "" {
			return nil, fmt.Errorf("%w: fixed_query 认证必须显式给出 query 参数名", ErrAuthConfig)
		}
		return nil, nil

	case model.AuthModeManualHeaders:
		return applyManualHeaders(ctx, header, in)

	case model.AuthModeLegacyAutoRealOnly:
		// 合成探活一律 config_error，需要显式 Calibration（计划 §P0-04 第 11 条、
		// §P0-11）。那条记录只是「历史上这么发过」，对探活而言仍是无依据地
		// 同时发两种认证 —— 而 §7.2 禁止它。
		//
		// 代价要说清：schema 1 的默认 auth_style 就是 auto，所以升级后**所有**
		// 未校准的旧站探活都会落到这里。这是规范刻意选的门禁方向 —— 让「这个站
		// 的认证方式还没确认」显式可见，而不是让探活用一种、真实请求用另一种。
		// 校准（P0-11）落地后这条路径就消失了。
		if in.Use == ResolveSyntheticProbe {
			return nil, fmt.Errorf("%w: 旧 auth_style=auto 尚未校准，"+
				"合成探活不能猜认证方式；请先运行一次校准", ErrAuthConfig)
		}
		key, err := upstreamKey(ctx, in.Values)
		if err != nil {
			return nil, err
		}
		header.Set("X-Api-Key", key)
		header.Set("Authorization", "Bearer "+key)
		return []string{"X-Api-Key", "Authorization"}, nil

	case model.AuthModeBearer, model.AuthModeXAPIKey, model.AuthModeAPIKey:
		key, err := upstreamKey(ctx, in.Values)
		if err != nil {
			return nil, err
		}
		name, value := singleAuthHeader(mode, key)
		header.Set(name, value)
		return []string{name}, nil

	default:
		// AuthModeAutoCalibrated 已在上面转换；走到这里说明加了新 mode 却
		// 没在这里处理。不能默默放过：那会发出一个无认证请求。
		return nil, fmt.Errorf("%w: 未实现的 auth mode %q", ErrAuthConfig, mode)
	}
}

func singleAuthHeader(mode model.AuthMode, key string) (string, string) {
	switch mode {
	case model.AuthModeBearer:
		return "Authorization", "Bearer " + key
	case model.AuthModeAPIKey:
		return "Api-Key", key
	default:
		return "X-Api-Key", key
	}
}

// upstreamKey 取上游 key。
//
// 值的字节校验不在这里：ApplyAuth 的出口统一验一次它写进 header 的每个值。
// 两处都验的话，其中一处必然逐渐与另一处分叉，而分叉的那一半是死代码 ——
// 看起来有防护，实际从没生效过。
func upstreamKey(ctx context.Context, values ValueResolver) (string, error) {
	if values == nil {
		return "", fmt.Errorf("%w: 未提供凭据来源", ErrAuthConfig)
	}
	resolved, err := values.ResolveValue(ctx, "UPSTREAM_API_KEY")
	if err != nil {
		// 不复述下层错误文本：它可能带凭据明文（见 valueError 的说明）。
		return "", fmt.Errorf("%w: 上游 api_key 不可用", ErrAuthConfig)
	}
	if len(resolved.Plain) == 0 {
		// 绝不静默发一个无认证请求：那会得到一个难以归因的 401 ——
		// 用户看到「认证失败」，而真正的问题是「key 没配」。
		return "", fmt.Errorf("%w: 上游 api_key 为空", ErrAuthConfig)
	}
	return string(resolved.Plain), nil
}

// validateHeaderCredential 挡住会构造出畸形请求的凭据。
//
// CR/LF 是请求头注入的实现手段：一个能改 Secret 值的人（管理界面就能改）
// 借此可以往请求里插任意头，甚至走私第二个请求。NUL 与其余控制字符同理 ——
// net/http 对它们的处理在不同版本间不完全一致，不该指望库来兜。
func validateHeaderCredential(value []byte) error {
	for _, character := range value {
		switch {
		case character == '\r', character == '\n':
			return errors.New("含 CR/LF（会构造出请求头注入）")
		case character == 0:
			return errors.New("含 NUL")
		case character < 0x20, character == 0x7f:
			return errors.New("含控制字符")
		}
	}
	return nil
}

// applyManualHeaders 渲染并写入自定义认证头，返回写过的头名。
//
// 与标准三种的区别只在「头名与值由配置给出」，但两条约束不变：
// 不得写标准认证别名（否则「只有一种 profile」这条约束失效），
// 且值本身要能安全进 header（由 ApplyAuth 的出口统一校验）。
func applyManualHeaders(ctx context.Context, header http.Header, in AuthInput) ([]string, error) {
	if len(in.Profile.ManualHeaders) == 0 {
		return nil, fmt.Errorf("%w: manual_headers 认证未配置任何头", ErrAuthConfig)
	}

	// 先全部渲染，再一次性写入。
	//
	// 边渲染边写的话，第三个头出错时前两个已经写进 header 了 —— 而调用方
	// 拿到错误后若继续发（不该，但 header 是共享的可变对象），发出去的
	// 就是一个「一半认证」的请求。
	rendered := make(map[string][]string, len(in.Profile.ManualHeaders))
	order := make([]string, 0, len(in.Profile.ManualHeaders))

	for _, template := range in.Profile.ManualHeaders {
		name := http.CanonicalHeaderKey(strings.TrimSpace(template.Name))
		if name == "" {
			return nil, fmt.Errorf("%w: manual auth header 缺少名字", ErrAuthConfig)
		}
		if model.IsAuthHeader(name) {
			return nil, fmt.Errorf("%w: manual_headers 不能写标准认证头 %q，"+
				"那会同时发出两种认证方式", ErrAuthConfig, name)
		}
		switch name {
		case "Host", "Content-Length", "Transfer-Encoding", "Connection":
			// Host 走 http.Request.Host（HostOverride），Content-Length 由
			// http 库按 body 重算，另两个是逐跳头。让配置写它们只会得到
			// 一个被静默忽略或畸形的请求。
			return nil, fmt.Errorf("%w: manual_headers 不能设置受保护头 %q", ErrAuthConfig, name)
		}

		values := make([]string, 0, len(template.Values))
		for _, raw := range template.Values {
			value, err := renderAuthValue(ctx, in.Values, name, raw)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		if _, seen := rendered[name]; !seen {
			order = append(order, name)
		}
		rendered[name] = append(rendered[name], values...)
	}

	for _, name := range order {
		header.Del(name)
		for _, value := range rendered[name] {
			header.Add(name, value)
		}
	}
	return order, nil
}

// renderAuthValue 渲染一个 manual header 值。
//
// 编译走 probetemplate 的同一条路：URL、header 与 body 里的占位符必须是
// 同一套语义与同一套转义规则。各写一份的话，同一个 Secret 在 header 与
// query 里会得到不同结果，而那类差异表现为上游 401 —— 排查方向完全错了。
//
// 值的字节校验不在这里做，由 ApplyAuth 的出口统一负责（见那里的说明）。
func renderAuthValue(ctx context.Context, values ValueResolver, name, raw string) (string, error) {
	if values == nil {
		return "", fmt.Errorf("%w: 未提供凭据来源", ErrAuthConfig)
	}
	compiled, err := probetemplate.CompileContent(model.EndpointMessages, probetemplate.TemplateContent{
		Method:  model.EndpointMessages.Method(),
		Headers: []model.HeaderTemplate{{Name: name, Values: []string{raw}}},
	})
	if err != nil {
		return "", fmt.Errorf("%w: manual auth header %q 模板无效", ErrAuthConfig, name)
	}

	tracker := &identityTracker{inner: values}
	request, err := compiled.Render(ctx, tracker)
	if err != nil {
		// 同 renderFixedQuery：只报占位符名，不复述下层文本
		// （probetemplate.Render 用 %w 包装 ValueResolver 的错误，
		// 而那条错误会落进 last_error 并显示在 UI 上）。
		//
		// 注意 Render 自己也会拒绝渲染后含控制字符的值，所以这条分支同时
		// 覆盖「Secret 带 CRLF」。ApplyAuth 出口的校验不因此多余 ——
		// 它覆盖的是标准三种 profile 那几条不经 probetemplate 的路径。
		return "", fmt.Errorf("%w: %s", ErrAuthConfig,
			(&valueError{placeholder: tracker.lastRequested}).Error())
	}
	return request.Header.Get(name), nil
}
