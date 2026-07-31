// Package router 实现选路：把入站 model 值匹配到 ModelName，再挑一个 Route。
package router

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

var (
	// ErrModelNotFound 未匹配到任何 ModelName（也没有兜底），应回 404。
	ErrModelNotFound = errors.New("未匹配到任何 ModelName")
	// ErrProtocolMismatch 入站端点协议与 ModelName 配置的协议不一致，应回 400。
	ErrProtocolMismatch = errors.New("入站端点协议与 ModelName 配置不一致")
	// ErrNoRouteAvailable 匹配到了 ModelName 但没有可用 Route，应回 503。
	ErrNoRouteAvailable = errors.New("没有可用的 Route")
)

// Candidate 是一个可投递的目标。
type Candidate struct {
	Route     *model.Route
	Upstream  *model.Upstream
	ModelName *model.ModelName
}

// HealthView 提供选路所需的健康状态。由 health 包实现，
// 这里只依赖接口，避免 router 与状态机循环依赖。
type HealthView interface {
	// State 返回 Route 的健康状态。未知的 Route 返回 StateUnknown。
	State(routeID int64) model.HealthState
	// InFlight 返回该 Route 当前在途请求数，用于并发上限判定。
	InFlight(routeID int64) int
	// CoolingDown 表示该 Route 处于 429 冷却期，本轮不选它（但不算 dead）。
	CoolingDown(routeID int64) bool
}

// Snapshot 是选路依赖的配置快照。调用方从 store 读一次，避免每请求查库。
type Snapshot struct {
	ModelNames []*model.ModelName
	Upstreams  map[int64]*model.Upstream
	// RoutesByModelName[modelNameID] = 该 ModelName 下的所有 Route
	RoutesByModelName map[int64][]*model.Route
}

// MatchModelName 按 §3.4 步骤 2 匹配 ModelName：
// 精确 → 前缀（最长优先）→ 兜底 → 未找到。
//
// 前缀按 name 长度降序是必须的：同时配了 "claude-opus" 与 "claude-opus-5" 时，
// 入站 "claude-opus-5-thinking" 应命中更具体的那个。若按任意顺序遍历，
// 结果取决于 map 迭代顺序，会变成随机行为。
func MatchModelName(snap *Snapshot, inModel string) (*model.ModelName, error) {
	if inModel == "" {
		return nil, fmt.Errorf("%w: 入站 model 为空", ErrModelNotFound)
	}

	var prefixes []*model.ModelName
	var fallback *model.ModelName

	for _, mn := range snap.ModelNames {
		if !mn.Enabled {
			continue
		}
		if mn.MatchMode == model.MatchExact && mn.Name == inModel {
			return mn, nil // 精确匹配优先级最高，直接返回
		}
		if mn.MatchMode == model.MatchPrefix && strings.HasPrefix(inModel, mn.Name) {
			prefixes = append(prefixes, mn)
		}
		if mn.IsFallback {
			fallback = mn
		}
	}

	if len(prefixes) > 0 {
		sort.Slice(prefixes, func(i, j int) bool {
			if len(prefixes[i].Name) != len(prefixes[j].Name) {
				return len(prefixes[i].Name) > len(prefixes[j].Name)
			}
			// 长度相同时按 ID 定序，保证结果稳定可复现
			return prefixes[i].ID < prefixes[j].ID
		})
		return prefixes[0], nil
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrModelNotFound, inModel)
}

// Select 按 §3.4 完成选路。endpointProto 是入站端点隐含的协议。
//
// 返回的 Candidate 已排除 dead 与冷却中的 Route。unknown 视为**可用**（乐观）：
// 重启后所有 Route 都是 unknown，若视为不可用则服务直接不可用。
func Select(snap *Snapshot, hv HealthView, inModel string,
	endpointProto model.Protocol) (*Candidate, error) {

	mn, err := MatchModelName(snap, inModel)
	if err != nil {
		return nil, err
	}
	// 协议必须一致。配错了要明确报错，而不是把 Anthropic 的 body
	// 发到 /v1/chat/completions —— 那会得到一个难以理解的上游 400。
	if mn.Protocol != endpointProto {
		return nil, fmt.Errorf("%w: 端点是 %s，但 ModelName %q 配置为 %s",
			ErrProtocolMismatch, endpointProto, mn.Name, mn.Protocol)
	}

	buckets, reason := viableBuckets(snap, hv, mn)
	if len(buckets) == 0 {
		return nil, fmt.Errorf("%w: ModelName %q %s", ErrNoRouteAvailable, mn.Name, reason)
	}

	// 按优先级升序取第一个有余量的桶。桶内已达并发上限的排除后若为空，
	// 溢出到下一优先级（§3.4 步骤 7）。
	for _, prio := range sortedKeys(buckets) {
		withRoom := make([]*model.Route, 0, len(buckets[prio]))
		for _, r := range buckets[prio] {
			if r.MaxConcurrency > 0 && hv.InFlight(r.ID) >= r.MaxConcurrency {
				continue
			}
			withRoom = append(withRoom, r)
		}
		if len(withRoom) == 0 {
			continue
		}
		chosen := weightedPick(withRoom)
		up := snap.Upstreams[chosen.UpstreamID]
		if up == nil {
			// 配置不一致（Route 指向已删除的 Upstream）。跳过而不是崩，
			// 让其余 Route 仍能服务。
			continue
		}
		return &Candidate{Route: chosen, Upstream: up, ModelName: mn}, nil
	}

	return nil, fmt.Errorf("%w: ModelName %q 的所有 Route 都已达并发上限",
		ErrNoRouteAvailable, mn.Name)
}

// viableBuckets 按 priority 把可用 Route 分桶。
// 第二个返回值是「没有可用 Route」时给人看的原因，便于在 503 里说明。
func viableBuckets(snap *Snapshot, hv HealthView, mn *model.ModelName) (map[int][]*model.Route, string) {
	all := snap.RoutesByModelName[mn.ID]
	if len(all) == 0 {
		return nil, "下没有绑定任何 Route"
	}

	buckets := map[int][]*model.Route{}
	var disabled, dead, cooling int
	for _, r := range all {
		switch {
		case !r.Enabled:
			disabled++
			continue
		case hv.State(r.ID) == model.StateDead:
			dead++
			continue
		case hv.CoolingDown(r.ID):
			cooling++
			continue
		}
		// 上游被手动停用时也不选。Route 启用但站停用是常见的临时下线方式。
		if up := snap.Upstreams[r.UpstreamID]; up == nil || !up.Enabled {
			disabled++
			continue
		}
		buckets[r.Priority] = append(buckets[r.Priority], r)
	}

	if len(buckets) == 0 {
		return nil, fmt.Sprintf("下的 %d 个 Route 均不可用（%d 个已停用，%d 个 dead，%d 个限流冷却中）",
			len(all), disabled, dead, cooling)
	}
	return buckets, ""
}

// DeadRoutesFor 返回该 ModelName 下所有 dead 的 Route，按优先级升序。
// 供半开放行用（§4.4c）：全部 dead 时选优先级最高的试探一次。
func DeadRoutesFor(snap *Snapshot, hv HealthView, mn *model.ModelName) []*model.Route {
	var out []*model.Route
	for _, r := range snap.RoutesByModelName[mn.ID] {
		if !r.Enabled {
			continue
		}
		if up := snap.Upstreams[r.UpstreamID]; up == nil || !up.Enabled {
			continue
		}
		if hv.State(r.ID) == model.StateDead {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// weightedPick 按 weight 加权随机。weight 已由 Validate 保证 ≥ 1。
func weightedPick(rs []*model.Route) *model.Route {
	if len(rs) == 1 {
		return rs[0]
	}
	total := 0
	for _, r := range rs {
		total += r.Weight
	}
	if total <= 0 {
		return rs[0] // 理论不可达（Validate 保证 weight ≥ 1），兜底防除零
	}
	n := rand.IntN(total)
	for _, r := range rs {
		n -= r.Weight
		if n < 0 {
			return r
		}
	}
	return rs[len(rs)-1]
}

func sortedKeys(m map[int][]*model.Route) []int {
	ks := make([]int, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Ints(ks)
	return ks
}

// BuildSnapshot 把 store 读出的扁平列表整理成选路用的索引结构。
func BuildSnapshot(mns []*model.ModelName, ups []*model.Upstream, routes []*model.Route) *Snapshot {
	snap := &Snapshot{
		ModelNames:        mns,
		Upstreams:         make(map[int64]*model.Upstream, len(ups)),
		RoutesByModelName: make(map[int64][]*model.Route),
	}
	for _, u := range ups {
		snap.Upstreams[u.ID] = u
	}
	for _, r := range routes {
		snap.RoutesByModelName[r.ModelNameID] = append(snap.RoutesByModelName[r.ModelNameID], r)
	}
	return snap
}
