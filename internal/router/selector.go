// Package router 实现选路：把入站 model 值匹配到 ModelName，再挑一个 Route。
package router

import (
	"errors"
	"fmt"
	"math"
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

	// HealthGeneration 是选路占位时的 RouteHealth 世代，供真实流量
	// Report 绑定；Forget 后同 id 新行世代不同，迟到结论必须丢弃。
	HealthGeneration uint64

	// release 是选中时占下的并发额度的释放函数，见 Release。
	release func()
}

// Release 归还选路时占用的并发额度。调用方**必须**在请求收尾时调一次
// （defer 即可），重复调用无害。
//
// 不释放的后果隐蔽且永久：该 Route 的在途计数只增不减，配了
// max_concurrency 之后会被永远排除在选路之外，且不会自愈。
func (c *Candidate) Release() {
	if c.release != nil {
		c.release()
	}
}

// NewCandidate 组装一个 Candidate，供半开放行使用（§4.4c）。
//
// 半开走的是 DeadRoutesFor 而不是 Select（它专挑 Select 排除掉的 dead
// Route），但拿到之后要和正常候选**完全一样**地被处理 —— 同样占并发额度、
// 同样 defer Release。
//
// 之所以要这个构造函数：release 是私有字段，而它必须私有 —— 公开的话
// 调用方可能自己塞一个 nil 进去，那就等于悄悄绕过了并发额度的归还。
// 让额度必须从 TryAcquire 来、且只能通过这个入口装进 Candidate，
// 「占了就一定会还」这条不变量才守得住。
func NewCandidate(rt *model.Route, up *model.Upstream,
	mn *model.ModelName, release func(), healthGeneration uint64) *Candidate {

	return &Candidate{Route: rt, Upstream: up, ModelName: mn,
		release: release, HealthGeneration: healthGeneration}
}

// HealthView 提供选路所需的健康状态。由 health 包实现，
// 这里只依赖接口，避免 router 与状态机循环依赖。
type HealthView interface {
	// State 返回 Route 的健康状态。未知的 Route 返回 StateUnknown。
	State(routeID int64) model.HealthState
	// CoolingDown 表示该 Route 处于 429 冷却期，本轮不选它（但不算 dead）。
	CoolingDown(routeID int64) bool
	// TryAcquire 原子地「检查并发上限并占位」。limit <= 0 表示不限。
	//
	// 之所以不是「读计数 + 由调用方判断」，是因为那两步之间有窗口：
	// 并发涌入时每个请求都读到涌入前的计数，于是全部通过检查。
	// 判定与占位必须在同一个临界区内完成。
	//
	// ok 为 true 时 release 非 nil，且必须在请求结束时调用一次。
	// generation 是占位时的 RouteHealth 世代，真实流量回写须带上它，
	// 以免 Forget 后同 id 新 Route 被迟到结论污染。
	// 实现须保证 release 可重复调用（多调无副作用）。
	TryAcquire(routeID int64, limit int) (release func(), generation uint64, ok bool)
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
// endpointProto 只用于挑兜底：精确与前缀匹配的协议校验留给 Select，
// 那里能给出「端点是 X 但配置为 Y」这种可操作的错误。而兜底是**隐式**选中的，
// 用户没有指名要它，报「你配错了」没有意义 —— 直接挑协议对得上的那个。
//
// 前缀按 name 长度降序是必须的：同时配了 "claude-opus" 与 "claude-opus-5" 时，
// 入站 "claude-opus-5-thinking" 应命中更具体的那个。若按任意顺序遍历，
// 结果取决于 map 迭代顺序，会变成随机行为。
//
// 已配置但停用的精确名视为「名称已命中」：不交给前缀或兜底去换另一条
// ModelName 的上游（客户端点名了该模型）。返回 ErrNoRouteAvailable。
func MatchModelName(snap *Snapshot, inModel string,
	endpointProto model.Protocol) (*model.ModelName, error) {

	if inModel == "" {
		return nil, fmt.Errorf("%w: 入站 model 为空", ErrModelNotFound)
	}
	nameMatches, fallback, disabledExact := orderedModelNameMatches(snap, inModel, endpointProto)
	if len(nameMatches) > 0 {
		return nameMatches[0], nil
	}
	if disabledExact {
		return nil, fmt.Errorf("%w: ModelName %q 已停用", ErrNoRouteAvailable, inModel)
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrModelNotFound, inModel)
}

// orderedModelNameMatches 拆出名称命中与兜底。
//
// nameMatches 顺序：精确（快照遍历顺序）→ 前缀（最长优先，同长按 ID）。
// SelectExcluding 在精确命中的 Route 全部被 exclude / 不可用时，只沿
// nameMatches 继续尝试前缀，避免「精确因 config_error 被排除」却丢掉仍能
// 匹配的健康前缀（§6.4）。名称已命中时不回落到兜底——兜底只服务「从未
// 命中名称」的入站 model，与 MatchModelName 一致。
//
// disabledExact 表示存在同名但 Enabled=false 的精确 ModelName，且没有任何
// 启用的精确命中。此时不得把前缀或兜底塞进 nameMatches/fallback 出口：
// 否则客户端点名的停用模型会被静默换成另一条上游。
func orderedModelNameMatches(snap *Snapshot, inModel string,
	endpointProto model.Protocol) (nameMatches []*model.ModelName, fallback *model.ModelName, disabledExact bool) {

	var exacts, prefixes []*model.ModelName

	for _, mn := range snap.ModelNames {
		// 空 name（含仅空白）不能参与匹配：Validate 会拒写入，但坏行仍可能
		// 经手工 SQL 等路径进快照。尤其 prefix + "" 时 strings.HasPrefix(s, "")
		// 对任意 s 都为 true，会把所有入站 model 吸进同一条 Route。
		if strings.TrimSpace(mn.Name) == "" {
			continue
		}
		if !mn.Enabled {
			if mn.MatchMode == model.MatchExact && mn.Name == inModel {
				disabledExact = true
			}
			continue
		}
		if mn.MatchMode == model.MatchExact && mn.Name == inModel {
			exacts = append(exacts, mn)
			continue
		}
		if mn.MatchMode == model.MatchPrefix && strings.HasPrefix(inModel, mn.Name) {
			prefixes = append(prefixes, mn)
		}
		// 只认协议对得上的兜底。schema 保证每协议至多一个，
		// 所以这里不会有「挑哪个」的歧义。
		if mn.IsFallback && mn.Protocol == endpointProto {
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
	}

	if len(exacts) > 0 {
		nameMatches = make([]*model.ModelName, 0, len(exacts)+len(prefixes))
		nameMatches = append(nameMatches, exacts...)
		nameMatches = append(nameMatches, prefixes...)
		return nameMatches, fallback, false
	}
	if disabledExact {
		// 点名停用精确名：不启用前缀、不清空后的兜底出口。
		return nil, nil, true
	}
	nameMatches = append([]*model.ModelName(nil), prefixes...)
	return nameMatches, fallback, false
}

// Select 按 §3.4 完成选路。endpointProto 是入站端点隐含的协议。
//
// 返回的 Candidate 已排除 dead 与冷却中的 Route。unknown 视为**可用**（乐观）：
// 重启后所有 Route 都是 unknown，若视为不可用则服务直接不可用。
func Select(snap *Snapshot, hv HealthView, inModel string,
	endpointProto model.Protocol) (*Candidate, error) {

	return SelectExcluding(snap, hv, inModel, endpointProto, nil)
}

// SelectExcluding 与 Select 相同，但跳过 exclude 里的 Route（§3.5 的重试）。
//
// 排除集由调用方维护而不是在这里记状态：选路必须是无状态的纯函数 ——
// 一次请求的重试历史不该影响下一次请求，而把「已试过」存在 selector 里
// 迟早会漏清理，表现是某个站在一次失败之后就再也选不到了。
//
// exclude 为 nil 或空时行为与 Select 完全一致，所以既有调用方与测试不受影响。
//
// 匹配顺序仍是精确 → 最长前缀 → 兜底；但若当前命中的 ModelName 在排除
// dead/冷却/exclude 后没有任何可用 Route，则继续尝试下一匹配（例如精确
// Route 因 config_error 被 selectFor 放入 exclude 后，仍可选健康前缀）。
// 有可用桶却全部达并发上限时不跨 ModelName 回落——那是额度耗尽，不是
// 「该匹配不合格」。
func SelectExcluding(snap *Snapshot, hv HealthView, inModel string,
	endpointProto model.Protocol, exclude map[int64]bool) (*Candidate, error) {

	if inModel == "" {
		return nil, fmt.Errorf("%w: 入站 model 为空", ErrModelNotFound)
	}
	nameMatches, fallback, disabledExact := orderedModelNameMatches(snap, inModel, endpointProto)
	matches := nameMatches
	if len(matches) == 0 {
		if disabledExact {
			return nil, fmt.Errorf("%w: ModelName %q 已停用", ErrNoRouteAvailable, inModel)
		}
		if fallback == nil {
			return nil, fmt.Errorf("%w: %q", ErrModelNotFound, inModel)
		}
		// 无名称命中时才用兜底；名称已命中但 Route 不可用时不回落兜底。
		matches = []*model.ModelName{fallback}
	}

	var lastNoRoute error
	for _, mn := range matches {
		// 协议必须一致。配错了要明确报错，而不是把 Anthropic 的 body
		// 发到 /v1/chat/completions —— 那会得到一个难以理解的上游 400。
		// 名称已命中时协议错误是 request-global，不跨到下一匹配。
		if mn.Protocol != endpointProto {
			return nil, fmt.Errorf("%w: 端点是 %s，但 ModelName %q 配置为 %s",
				ErrProtocolMismatch, endpointProto, mn.Name, mn.Protocol)
		}

		buckets, reason := viableBuckets(snap, hv, mn, exclude)
		if len(buckets) == 0 {
			lastNoRoute = fmt.Errorf("%w: ModelName %q %s", ErrNoRouteAvailable, mn.Name, reason)
			continue
		}

		// 按优先级升序找第一个能占到额度的 Route。
		//
		// 桶内挑中的那个若占不到（已达上限，或刚被并发请求抢先），就把它从
		// 候选池里剔掉、在桶内重挑，而不是直接溢出到下一优先级 —— 后者会让
		// 同桶里明明还有余量的站被白白跳过。整桶都占不到才溢出（§3.4 步骤 7）。
		for _, prio := range sortedKeys(buckets) {
			pool := buckets[prio]
			for len(pool) > 0 {
				i := weightedPick(pool)
				chosen := pool[i]
				// 交换删除。buckets 是 viableBuckets 每次现建的，改它不会
				// 碰到配置快照；加权随机也不依赖元素顺序。
				pool[i] = pool[len(pool)-1]
				pool = pool[:len(pool)-1]

				up := snap.Upstreams[chosen.UpstreamID]
				if up == nil {
					// 配置不一致（Route 指向已删除的 Upstream）。跳过而不是崩，
					// 让其余 Route 仍能服务。
					continue
				}
				// 占位与判定在 TryAcquire 内部一次完成，中间没有让并发请求
				// 挤进来的窗口。
				release, gen, ok := hv.TryAcquire(chosen.ID, chosen.MaxConcurrency)
				if !ok {
					continue
				}
				return &Candidate{Route: chosen, Upstream: up,
					ModelName: mn, release: release, HealthGeneration: gen}, nil
			}
		}

		// 有候选但全达并发上限：不跨到前缀/兜底（额度问题 ≠ 匹配不合格）。
		return nil, fmt.Errorf("%w: ModelName %q 的所有 Route 都已达并发上限",
			ErrNoRouteAvailable, mn.Name)
	}

	if lastNoRoute != nil {
		return nil, lastNoRoute
	}
	return nil, fmt.Errorf("%w: %q", ErrModelNotFound, inModel)
}

// viableBuckets 按 priority 把可用 Route 分桶。
// 第二个返回值是「没有可用 Route」时给人看的原因，便于在 503 里说明。
//
// exclude 是本次请求已经试过的 Route（§3.5 重试）。它单独计数并写进原因里 ——
// 「3 个 Route 都试过了」与「3 个 Route 都 dead」是完全不同的处境，
// 混成一句话会让人去查健康状态，而实际该看的是那几次尝试各自失败在哪。
func viableBuckets(snap *Snapshot, hv HealthView, mn *model.ModelName,
	exclude map[int64]bool) (map[int][]*model.Route, string) {

	all := snap.RoutesByModelName[mn.ID]
	if len(all) == 0 {
		return nil, "下没有绑定任何 Route"
	}

	buckets := map[int][]*model.Route{}
	var disabled, dead, cooling, tried int
	for _, r := range all {
		switch {
		case exclude[r.ID]:
			tried++
			continue
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
		reason := fmt.Sprintf("下的 %d 个 Route 均不可用（%d 个已停用，%d 个 dead，%d 个限流冷却中",
			len(all), disabled, dead, cooling)
		if tried > 0 {
			reason += fmt.Sprintf("，%d 个本次已试过", tried)
		}
		return nil, reason + "）"
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

// weightedPick 按 weight 加权随机，返回**下标**。
// 返回下标而不是元素，是为了让调用方能在占额度失败后把它剔出候选池重挑。
// weight 已由 Validate 保证 ≥ 1。
//
// 累加用 int64，避免多个接近 MaxInt 的 weight 在 int 上绕回成
// 负/零 total，从而总是返回下标 0 或让 IntN panic。若 int64 仍放不下，
// 按比例右移后再抽，保证正权重路由仍有机会被选中。
func weightedPick(rs []*model.Route) int {
	if len(rs) == 1 {
		return 0
	}
	total, shift, ok := weightTotal(rs)
	if !ok || total <= 0 {
		return 0 // 理论不可达（Validate 保证 weight ≥ 1），兜底防除零
	}
	n := rand.Int64N(total)
	for i, r := range rs {
		n -= scaledWeight(r.Weight, shift)
		if n < 0 {
			return i
		}
	}
	return len(rs) - 1
}

// weightTotal 在 int64 上求权重和。若直接相加会溢出，则统一右移
// 直到和能放入 int64；返回的 shift 须用于抽签时的权重缩放。
func weightTotal(rs []*model.Route) (total int64, shift uint, ok bool) {
	for shift = 0; shift < 63; shift++ {
		total = 0
		overflow := false
		for _, r := range rs {
			w := scaledWeight(r.Weight, shift)
			if w > 0 && total > math.MaxInt64-w {
				overflow = true
				break
			}
			total += w
		}
		if !overflow {
			return total, shift, true
		}
	}
	return 0, 0, false
}

func scaledWeight(weight int, shift uint) int64 {
	w := int64(weight) >> shift
	// 右移后不要把正权重抹成 0，否则小权重路由会从抽签中消失。
	if weight > 0 && w == 0 {
		return 1
	}
	return w
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
