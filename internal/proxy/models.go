package proxy

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/279814/relay-gate/internal/model"
)

// handleModels 处理 GET /v1/models（§3.1）。
//
// 返回已配置的 ModelName 列表，供客户端（如 ccswitch）获取可用模型。
// 本地应答，不转发到上游。
//
// 响应格式遵循 OpenAI /v1/models 的结构（只返回必需字段）：
//
//	{
//	  "object": "list",
//	  "data": [
//	    {"id": "claude-opus-5", "object": "model", "owned_by": "relay-gate"},
//	    ...
//	  ]
//	}
func (h *Handler) handleModels(w http.ResponseWriter, r *http.Request) {
	// 鉴权与透传端点同一套。§5.2f 的要求是无条件的：服务暴露公网时
	// 这是唯一屏障，而模型清单泄露的是「这里有哪些模型可白嫖」。
	// 缺鉴权时 ccswitch 那侧的表现是拿不到列表，而不是静默降级 ——
	// 它本来就会带上 key（否则后续的转发请求也过不去）。
	if !h.authOK(r) {
		writeAPIError(w, http.StatusUnauthorized, model.ProtoAnthropic,
			"authentication_error", "无效的 API key")
		return
	}

	// **刻意不走总闸**（§4.8），与 count_tokens 和三个透传端点都不同。
	//
	// 暂停的目的是「不用时不浪费额度」，而这个端点纯粹本地读配置，
	// 零上游成本、零 token。暂停期间仍然回列表，用户才能在管理界面上
	// 对照着「配了哪些模型」去调整配置 —— 那恰恰是暂停时最常做的事。
	//
	// 客户端不会因此误判服务可用：它一旦真的发请求，拿到的是
	// 503 + X-Relay-State: paused，原因明确。

	snap, err := h.cfg.Snapshot()
	if err != nil {
		h.log.Error("读取配置快照失败", "err", err)
		writeAPIError(w, http.StatusInternalServerError, model.ProtoAnthropic,
			"api_error", "内部错误")
		return
	}

	// 只返回启用的 ModelName。禁用的不该出现在列表里，
	// 否则客户端会选中它、请求却 404。
	//
	// 不按健康状态过滤（§10.3 留的问题）：一个暂时 dead 的模型在列表里
	// 消失，客户端可能把它从自己的配置里也去掉，而它几十秒后就恢复了。
	// 列表是「配了什么」，健康状态是「现在能不能用」，混在一起会让
	// 一次短暂故障变成一次配置丢失。
	names := make([]string, 0, len(snap.ModelNames))
	for _, mn := range snap.ModelNames {
		if mn.Enabled {
			names = append(names, mn.Name)
		}
	}
	// 定序输出。snap.ModelNames 的顺序来自库里的查询，稳定的列表
	// 让客户端侧的 diff 与人工比对都不会因为顺序抖动而产生噪声。
	sort.Strings(names)

	// 必须是非 nil 的切片：空配置要序列化成 "data":[] 而不是 null，
	// 客户端多半直接 for 循环，null 会让它崩在启动阶段。
	items := make([]map[string]any, 0, len(names))
	for _, n := range names {
		items = append(items, map[string]any{
			"id":       n,
			"object":   "model",
			"owned_by": "relay-gate",
			// 不给 created：ModelName.CreatedAt 是**本地配置**的时间，
			// 不是模型发布时间，回显出去只会误导。
		})
	}

	resp := map[string]any{
		"object": "list",
		"data":   items,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
