package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

// sampleProbeHeaders 把一条真实样本的入站头导出成探活头模板（§3.6.4）。
//
// 为什么这个功能存在：M0 实测到按 user-agent 白名单拦截的站，探活头
// 长得不像真实 Claude Code 就会被 401，于是一个完全可用的站被判死。
// 手写探活头等于猜，而 M0 已经证明猜会把好站踢出池子。样本里存的是
// **真实请求的完整头集合**，从它导出才是有依据的做法。
//
// 只返回建议值，不直接写库：让用户先看一眼再决定存不存 —— 这份头会
// 影响该站所有探活的成败，静默生效的话，一次误导出就能让整站判死。
func (s *Server) sampleProbeHeaders(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	smp, err := s.st.GetSample(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}

	tmpl, skipped := probeHeadersFromSample(smp.InHeaders)
	writeJSON(w, http.StatusOK, map[string]any{
		"sample_id":   id,
		"upstream_id": smp.UpstreamID,
		"headers":     tmpl,
		// skipped 要显式回报而不是静默丢弃：用户看到导出的模板里没有
		// Authorization 时，需要知道那是**刻意**排除的，而不是样本里本来就没有。
		// 不说清的话，下一步就是手动把它加回去 —— 那正是这里要防的事。
		"skipped":  skipped,
		"defaults": probe.DefaultHeaderTemplate(),
	})
}

// probeHeadersFromSample 从样本的入站头里挑出适合做探活模板的部分。
//
// 返回 skipped 是接口的一部分，理由见调用处。
func probeHeadersFromSample(h http.Header) (tmpl map[string]string, skipped []string) {
	tmpl = map[string]string{}
	for name, vals := range h {
		if len(vals) == 0 {
			continue
		}
		lower := strings.ToLower(name)

		// 鉴权头一律排除。
		//
		// 样本里这些值**已经脱敏**（sample.RedactHeaders），所以存进
		// probe_headers 的会是 `sk-abcd…wxyz` 这种打了码的串 —— 拿它当
		// key 去探活，结果是整站 401、被判死，而原因极难看出来
		// （界面上显示的是「鉴权失败」，用户会去查真 key 对不对）。
		//
		// 更根本的理由：探活的 key 必须来自加密存储的 upstream.api_key
		// （probe/headers.go 的 injectAuth），而 probe_headers 是明文 JSON。
		// 让它带 key 等于开了第二个不受加密保护的 key 来源。
		//
		// 这里自己过滤而不是依赖下游（buildHeaders 会跳过、model.Validate
		// 会拒绝）：那两处是纵深防御，而这里是**语义**上的正确 ——
		// 导出一个注定无效的头，本身就是错的。
		if model.IsAuthHeader(lower) {
			skipped = append(skipped, name)
			continue
		}
		if skipHeaderForProbe[lower] {
			skipped = append(skipped, name)
			continue
		}
		tmpl[lower] = vals[0]
	}
	sort.Strings(skipped)
	return tmpl, skipped
}

// skipHeaderForProbe 是不该进探活模板的头。
//
// 分三类，理由不同：
//   - 逐请求变化的：content-length（探活 body 长度不同）、
//     content-type（探活自己按协议设）
//   - 由 Transport 管的：host、connection、accept-encoding ——
//     手工设这些会与 Go 的 http.Transport 打架（它会自己填，
//     而重复的 Host 头是协议错误）
//   - 与内容绑定的：anthropic-version 之类由 buildHeaders 按协议设，
//     从样本抄反而会把一个协议的版本头带到另一个协议上
var skipHeaderForProbe = map[string]bool{
	"host":              true,
	"content-length":    true,
	"content-type":      true,
	"connection":        true,
	"accept-encoding":   true,
	"transfer-encoding": true,
	// cookie 可能带会话凭据，与鉴权头同理
	"cookie": true,
	// 这两个是本网关自己加的，不属于上游指纹
	"x-relay-state":   true,
	"x-forwarded-for": true,
}
