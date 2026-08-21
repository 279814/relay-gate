package probe

import (
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

// 探活头的来源（§3.6.4、§8.5）。
//
// 头集合本身**不在这个文件里** —— 它出自内置 manifest（builtin/）或用户配的
// Recipe，由 execute.go 渲染。这里只剩两件事：Upstream 级覆盖，以及把
// 「默认头长什么样」这个问题转给 manifest 回答。
//
// P0-06 之前这里有一份硬编码的 defaultProbeHeaders 与 buildHeaders。删掉它们
// 的理由不是清理癖：那份硬编码与 manifest 并存就是探活头的两份真相，而两份
// 真相中「界面上展示的那一份」与「实际发出去的那一份」分叉时，用户会照着
// 界面调指纹却看不到任何效果。计划原本把 buildHeaders 排到 P0-17 删除
// （P0-05 验收条款），前提是它还有 DefaultHeaderTemplate 这个生产调用方；
// 本次改动让它失去了那个调用方，于是提前删。

// applyUpstreamHeaderOverrides 叠加 Upstream 级 probe_headers（§3.6.4）。
//
// 给「按 UA 白名单拦截」这类站单独调指纹用。三条语义：
//
//   - 空值 = 删掉这个头。有站会因为多一个头而拒绝请求，所以需要一个能减头的
//     手段，而不只是加和改。
//   - 认证头静默跳过。这里在探活的热路径上，没有能把错误呈现给用户的位置；
//     配置层已经拒绝了这种输入（model.Validate），这里是纵深防御 ——
//     万一有人手改了库，也不能让明文 key 生效。
//   - 其余 Set（覆盖而非追加）：probe_headers 是 map[string]string，
//     一个名字只有一个值，追加会在重复调用时越积越多。
//
// 作用在渲染出的头上而不是在模板层：probe_headers 是**站级**开关，而模板
// 可能来自 Route 级配方。放进模板编译的话，同一个站的两条 Route 会各自
// 编译一遍同样的覆盖，而其中一条忘了就是「这个站有一半探活带错指纹」。
func applyUpstreamHeaderOverrides(header http.Header, up *model.Upstream) {
	if up == nil {
		return
	}
	for name, value := range up.ProbeHeaders {
		if model.IsAuthHeader(name) {
			continue
		}
		if value == "" {
			header.Del(name)
			continue
		}
		header.Set(name, value)
	}
}

// DefaultHeaderTemplate 返回默认探活头模板，供管理界面展示与编辑。
//
// 取自内置 messages compact 模板（P0-06 的 manifest）：界面上展示的「默认头」
// 必须与探活实际发的是同一份。各列一份的后果是用户照着界面调指纹，而实际
// 发出去的是另一套 —— 排查时对着界面完全看不出问题。
//
// manifest 加载失败时返回 nil 而不是一份退化的硬编码：那种「看起来有默认值」
// 会掩盖真正的问题（embed 的数据文件坏了）。探活路径上同一个失败会以错误
// 形式暴露（LoadBuiltinTemplates 的返回值），而那才是该失败的地方。
//
// 返回新 map，调用方改它不影响任何人。
func DefaultHeaderTemplate() map[string]string {
	set, err := LoadBuiltinTemplates()
	if err != nil {
		return nil
	}
	compact, err := set.Compact(model.EndpointMessages)
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(compact.Headers))
	for _, header := range compact.Headers {
		out[strings.ToLower(header.Name)] = strings.Join(header.Values, ",")
	}
	return out
}
