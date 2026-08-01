package probe

import (
	"sort"
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// Cost 累计探活开销（§5.2d）。
//
// 为什么需要它：当前只有状态没有计数，无法回答「探活策略是不是太激进」。
// 而这个项目的探活是刻意频繁的（dead 站 20s 一次 L1），激进本身是设计选择 ——
// 但那要求代价可见，否则就只是「看起来没问题」。
//
// 计数在内存里累加、按天分桶，由 CostPersister 周期落库（与健康状态同一套
// 做法）。落库是必须的：**「今日」的语义要跨重启**。纯内存计数在每次重启后
// 归零，于是「今日 L1 = 12 次」这种数字会在一天里越报越少 —— 一个会骗人的
// 计数器比没有计数器更糟。
type Cost struct {
	mu sync.Mutex
	// day 是当前累计的日期（本地时区 YYYY-MM-DD）。跨天时归零重开。
	day string
	// perRoute 是各 Route 明细，§5.2d 明确要求「各 Route 明细」。
	perRoute map[int64]*RouteCost
	// l1 是站级的，不挂在 Route 上：一次 L1 被同站多个 Route 共享
	// （scheduler.beginL1 收敛），记到 Route 上会把一次请求算成 N 次。
	perUpstream map[int64]*UpstreamCost

	now func() time.Time // 测试注入时钟
}

// RouteCost 是单个 Route 的 L2 开销。
//
// 只有 L2 花 token：L1 是 GET /v1/models，零 token（§4.1）。
type RouteCost struct {
	RouteID int64 `json:"route_id"`
	L2Count int64 `json:"l2_count"`
	// EstTokens 是估算值，不是账单。见 estimateL2Tokens 的说明。
	EstTokens int64 `json:"est_tokens"`
	// L2Failed 单独计数：失败的探活同样花钱（请求已经发出去了），
	// 而「失败占比高」是策略过激的直接信号 —— 探一个死站 100 次，
	// 100 次都失败，那 100 次的 token 是纯浪费。
	L2Failed int64 `json:"l2_failed"`
	LastL2At int64 `json:"last_l2_at"`
}

// UpstreamCost 是单个 Upstream 的 L1 次数。
type UpstreamCost struct {
	UpstreamID int64 `json:"upstream_id"`
	L1Count    int64 `json:"l1_count"`
	L1Failed   int64 `json:"l1_failed"`
	LastL1At   int64 `json:"last_l1_at"`
}

func NewCost() *Cost {
	return &Cost{
		perRoute:    map[int64]*RouteCost{},
		perUpstream: map[int64]*UpstreamCost{},
		now:         time.Now,
	}
}

// AddL1 记一次 L1。零 token，只计次数。
func (c *Cost) AddL1(upstreamID int64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollLocked()

	uc := c.perUpstream[upstreamID]
	if uc == nil {
		uc = &UpstreamCost{UpstreamID: upstreamID}
		c.perUpstream[upstreamID] = uc
	}
	uc.L1Count++
	if !ok {
		uc.L1Failed++
	}
	uc.LastL1At = c.now().UnixMilli()
}

// AddL2 记一次 L2 及其估算 token。
func (c *Cost) AddL2(routeID int64, ok bool, estTokens int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollLocked()

	rc := c.perRoute[routeID]
	if rc == nil {
		rc = &RouteCost{RouteID: routeID}
		c.perRoute[routeID] = rc
	}
	rc.L2Count++
	if !ok {
		rc.L2Failed++
	}
	rc.EstTokens += int64(estTokens)
	rc.LastL2At = c.now().UnixMilli()
}

// rollLocked 跨天时清零，并在首次调用时把 day 初始化成今天。
// 调用方必须已持有锁。
//
// 每个读写入口都必须先调它，两个理由：
//   - 只在读路径调的话，跨天后第一次 Add 会把新一天的计数加进旧桶，
//     而那个桶随后才被清空 —— 这次探活就凭空消失了
//   - day 的零值是空串，与任何日期都不相等，所以首次调用会走清零分支，
//     顺带完成初始化。少调一处就是「计数永远是 0」
//
// 按本地时区分天而不是 UTC：看这个数字的人是按自己的一天来判断
// 「今天探了多少次」的。
func (c *Cost) rollLocked() {
	today := c.now().Format("2006-01-02")
	if c.day == today {
		return
	}
	c.day = today
	c.perRoute = map[int64]*RouteCost{}
	c.perUpstream = map[int64]*UpstreamCost{}
}

// CostSnapshot 是成本视图的对外形状。
type CostSnapshot struct {
	Day string `json:"day"`
	// 汇总。§5.2d 的原话是「今日 L1/L2 次数、估算 token」。
	L1Count   int64 `json:"l1_count"`
	L1Failed  int64 `json:"l1_failed"`
	L2Count   int64 `json:"l2_count"`
	L2Failed  int64 `json:"l2_failed"`
	EstTokens int64 `json:"est_tokens"`

	Routes    []RouteCost    `json:"routes"`
	Upstreams []UpstreamCost `json:"upstreams"`
}

// Snapshot 返回当日成本快照，明细按 ID 升序（稳定输出便于 UI 与测试）。
func (c *Cost) Snapshot() CostSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollLocked()

	out := CostSnapshot{
		Day:       c.day,
		Routes:    make([]RouteCost, 0, len(c.perRoute)),
		Upstreams: make([]UpstreamCost, 0, len(c.perUpstream)),
	}
	for _, rc := range c.perRoute {
		out.Routes = append(out.Routes, *rc)
		out.L2Count += rc.L2Count
		out.L2Failed += rc.L2Failed
		out.EstTokens += rc.EstTokens
	}
	for _, uc := range c.perUpstream {
		out.Upstreams = append(out.Upstreams, *uc)
		out.L1Count += uc.L1Count
		out.L1Failed += uc.L1Failed
	}
	sort.Slice(out.Routes, func(i, j int) bool {
		return out.Routes[i].RouteID < out.Routes[j].RouteID
	})
	sort.Slice(out.Upstreams, func(i, j int) bool {
		return out.Upstreams[i].UpstreamID < out.Upstreams[j].UpstreamID
	})
	return out
}

// Restore 用落库的快照重建当日计数，供启动时调用。
//
// 只在日期相同时接受：库里存的是昨天的数据时，「今日」应当从零开始。
func (c *Cost) Restore(snap CostSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if snap.Day != c.now().Format("2006-01-02") {
		return
	}
	c.day = snap.Day
	for i := range snap.Routes {
		rc := snap.Routes[i]
		c.perRoute[rc.RouteID] = &rc
	}
	for i := range snap.Upstreams {
		uc := snap.Upstreams[i]
		c.perUpstream[uc.UpstreamID] = &uc
	}
}

// estimateL2Tokens 估算一次 L2 探活消耗的 token。
//
// **是估算，不是账单。** 用途是判断策略是否过激（探活次数 × 每次的量级），
// 那只需要正确的量级；要精确值得去看各站的计费页，而公益站多半也不提供。
//
// 输入按 4 字符 ≈ 1 token 折算，与 count_tokens 的本地兜底用同一个系数
// （proxy/count_tokens.go）—— 两处对不上的话，同一个 prompt 会给出两个数字。
// 输出按 max_tokens 的上限计：实际生成通常更少（判定一出就断流，§4.1），
// 所以这是**上界**，用于成本估算时宁可高估。
//
// 固定开销那部分（协议骨架 + system 之类）不计：探活 body 是我们自己
// 构造的最小请求，除了 prompt 几乎没有别的内容。
func estimateL2Tokens(mn *model.ModelName) int {
	prompt := mn.ProbePrompt
	if prompt == "" {
		prompt = "1+1=?"
	}
	maxTok := mn.ProbeMaxTokens
	if maxTok <= 0 {
		maxTok = 1
	}
	// +3 是消息骨架（role/content 的结构性 token）的粗略常数。
	in := len([]rune(prompt))/4 + 3
	return in + maxTok
}
