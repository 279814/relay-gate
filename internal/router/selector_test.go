package router

import (
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// fakeHealth 让测试能精确控制每个 Route 的状态。
//
// TryAcquire 复刻生产实现的语义（health.Tracker）：判定与占位在同一步完成，
// 释放后计数回落。测试直接写 inflight 即可预置「已有 N 个在途」。
type fakeHealth struct {
	mu       sync.Mutex
	states   map[int64]model.HealthState
	inflight map[int64]int
	cooling  map[int64]bool
}

func newFakeHealth() *fakeHealth {
	return &fakeHealth{
		states:   map[int64]model.HealthState{},
		inflight: map[int64]int{},
		cooling:  map[int64]bool{},
	}
}

func (f *fakeHealth) State(id int64) model.HealthState {
	if s, ok := f.states[id]; ok {
		return s
	}
	return model.StateUnknown // 与生产一致：未知即 unknown
}
func (f *fakeHealth) CoolingDown(id int64) bool { return f.cooling[id] }

func (f *fakeHealth) TryAcquire(id int64, limit int) (func(), uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if limit > 0 && f.inflight[id] >= limit {
		return nil, 0, false
	}
	f.inflight[id]++
	// once 是接口契约的一部分（release 须可重复调用），替身也照做 ——
	// 否则测试会在一个生产上不存在的行为上通过或失败。
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.inflight[id]--
		})
	}, 1, true
}

func (f *fakeHealth) inFlight(id int64) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inflight[id]
}

// 构造：1 个 ModelName（anthropic），3 个站，3 条 Route（优先级 1/2/3）
func basicSnapshot() *Snapshot {
	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	ups := []*model.Upstream{
		{ID: 10, Name: "s1", BaseURL: "https://s1.com", Enabled: true},
		{ID: 20, Name: "s2", BaseURL: "https://s2.com", Enabled: true},
		{ID: 30, Name: "s3", BaseURL: "https://s3.com", Enabled: true},
	}
	routes := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 100, Enabled: true},
		{ID: 200, ModelNameID: 1, UpstreamID: 20, Priority: 2, Weight: 100, Enabled: true},
		{ID: 300, ModelNameID: 1, UpstreamID: 30, Priority: 3, Weight: 100, Enabled: true},
	}
	return BuildSnapshot([]*model.ModelName{mn}, ups, routes)
}

// 优先级 1 > 2 > 3，高优先级可用时绝不选低的。
func TestSelect_PrefersHighestPriority(t *testing.T) {
	snap := basicSnapshot()
	hv := newFakeHealth()

	for i := 0; i < 50; i++ {
		c, err := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
		if err != nil {
			t.Fatal(err)
		}
		if c.Route.ID != 100 {
			t.Fatalf("应始终选优先级 1 的 Route 100，得到 %d", c.Route.ID)
		}
	}
}

// dead 的跳过，落到下一优先级。这是整个项目的核心价值。
func TestSelect_SkipsDeadFallsToNextPriority(t *testing.T) {
	snap := basicSnapshot()
	hv := newFakeHealth()

	hv.states[100] = model.StateDead
	c, err := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if c.Route.ID != 200 {
		t.Fatalf("优先级 1 dead 后应选 200，得到 %d", c.Route.ID)
	}

	hv.states[200] = model.StateDead
	c, err = Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if c.Route.ID != 300 {
		t.Fatalf("1、2 都 dead 后应选 300，得到 %d", c.Route.ID)
	}

	// 全 dead → 503，且原因要说清楚
	hv.states[300] = model.StateDead
	_, err = Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
	if !errors.Is(err, ErrNoRouteAvailable) {
		t.Fatalf("全部 dead 应返回 ErrNoRouteAvailable，得到 %v", err)
	}
	if !strings.Contains(err.Error(), "3 个 dead") {
		t.Errorf("错误信息应说明有几个 dead，得到：%v", err)
	}
}

// unknown 必须视为可用（乐观）。否则重启后所有 Route 都是 unknown，
// 服务直接不可用。
func TestSelect_UnknownIsUsable(t *testing.T) {
	snap := basicSnapshot()
	hv := newFakeHealth()
	hv.states[100] = model.StateUnknown
	hv.states[200] = model.StateAlive

	c, err := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if c.Route.ID != 100 {
		t.Errorf("unknown 应视为可用且优先级更高，得到 %d", c.Route.ID)
	}
}

// 429 冷却期内不选它，但它不是 dead —— 冷却结束后应自动恢复参与选路。
func TestSelect_SkipsCoolingDown(t *testing.T) {
	snap := basicSnapshot()
	hv := newFakeHealth()

	hv.cooling[100] = true
	c, _ := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
	if c.Route.ID != 200 {
		t.Errorf("冷却中的应跳过，得到 %d", c.Route.ID)
	}

	hv.cooling[100] = false
	c, _ = Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
	if c.Route.ID != 100 {
		t.Errorf("冷却结束后应重新参与选路，得到 %d", c.Route.ID)
	}
}

// 达到并发上限时溢出到下一优先级（§3.4 步骤 7）。
func TestSelect_ConcurrencyOverflow(t *testing.T) {
	snap := basicSnapshot()
	snap.RoutesByModelName[1][0].MaxConcurrency = 2
	hv := newFakeHealth()

	hv.inflight[100] = 1
	if c, _ := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic); c.Route.ID != 100 {
		t.Errorf("未达上限应仍选 100，得到 %d", c.Route.ID)
	}

	hv.inflight[100] = 2 // 达到上限
	if c, _ := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic); c.Route.ID != 200 {
		t.Errorf("达上限应溢出到 200，得到 %d", c.Route.ID)
	}

	// MaxConcurrency=0 表示不限，再高的在途也不该溢出
	snap.RoutesByModelName[1][0].MaxConcurrency = 0
	hv.inflight[100] = 9999
	if c, _ := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic); c.Route.ID != 100 {
		t.Errorf("MaxConcurrency=0 应视为不限，得到 %d", c.Route.ID)
	}
}

// 额度必须在 Release 后归还，否则一次请求就永久占住一格，
// 配了 max_concurrency 的 Route 会越用越窄直到彻底选不到。
func TestSelect_ReleaseReturnsQuota(t *testing.T) {
	snap := basicSnapshot()
	snap.RoutesByModelName[1][0].MaxConcurrency = 1
	hv := newFakeHealth()

	c, err := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if c.Route.ID != 100 || hv.inFlight(100) != 1 {
		t.Fatalf("选中即应占位：route=%d inflight=%d", c.Route.ID, hv.inFlight(100))
	}
	// 占着的时候第二个请求必须溢出
	if c2, _ := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic); c2.Route.ID != 200 {
		t.Errorf("额度被占时应溢出到 200，得到 %d", c2.Route.ID)
	}

	c.Release()
	c.Release() // 重复释放不能减穿
	if got := hv.inFlight(100); got != 0 {
		t.Fatalf("释放后在途应归零，得到 %d", got)
	}
	if c3, _ := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic); c3.Route.ID != 100 {
		t.Errorf("额度归还后应重新选到 100，得到 %d", c3.Route.ID)
	}
}

// 并发爆发时不得突破 max_concurrency。
//
// 曾经的 bug：Select 只读 InFlight 做判断，真正的登记由调用方在 Select
// **返回之后**才做。一批同时到达的请求全都读到爆发前的计数、全都通过检查，
// max_concurrency=1 的站会被一次打进 N 个 —— 而配这个上限的站，往往正是
// 那种多开一路就限流甚至封号的公益站。判定与占位必须是同一步。
func TestSelect_ConcurrencyLimitHoldsUnderBurst(t *testing.T) {
	const limit = 3
	const burst = 60

	snap := basicSnapshot()
	// 只留一条 Route，避免溢出掩盖了超发
	snap.RoutesByModelName[1] = snap.RoutesByModelName[1][:1]
	snap.RoutesByModelName[1][0].MaxConcurrency = limit
	hv := newFakeHealth()

	var mu sync.Mutex
	var live, peak int
	var granted int

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	for i := 0; i < burst; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait() // 卡在同一个起跑线上，最大化重叠

			c, err := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
			if err != nil {
				return // 达上限被拒是正确行为
			}
			mu.Lock()
			granted++
			live++
			if live > peak {
				peak = live
			}
			mu.Unlock()

			// 持有一会儿，制造真实的重叠窗口
			time.Sleep(time.Millisecond)

			mu.Lock()
			live--
			mu.Unlock()
			c.Release()
		}()
	}
	start.Done()
	done.Wait()

	if peak > limit {
		t.Errorf("同时在途峰值 %d 超过了 max_concurrency=%d（共放行 %d 个）",
			peak, limit, granted)
	}
	if granted == 0 {
		t.Error("一个都没放行，上限判定过严")
	}
	if got := hv.inFlight(100); got != 0 {
		t.Errorf("全部结束后在途应归零，得到 %d", got)
	}
}

// 同一优先级里有别的站有余量时，不该越级溢出到低优先级。
//
// 桶内「挑中的那个正好满了」是常态（加权随机 + 并发），若因此直接跳到
// 下一优先级，等于把同档次的备用站白白浪费掉 —— 优先级的意义就没了。
func TestSelect_RepicksWithinBucketBeforeSpilling(t *testing.T) {
	mn := &model.ModelName{ID: 1, Name: "m", Protocol: model.ProtoAnthropic,
		MatchMode: model.MatchExact, Enabled: true}
	ups := []*model.Upstream{
		{ID: 10, Enabled: true}, {ID: 20, Enabled: true}, {ID: 30, Enabled: true},
	}
	routes := []*model.Route{
		// 同优先级两条，都限 1 并发
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 100,
			MaxConcurrency: 1, Enabled: true},
		{ID: 200, ModelNameID: 1, UpstreamID: 20, Priority: 1, Weight: 100,
			MaxConcurrency: 1, Enabled: true},
		// 低优先级的兜底，只有前两条都满了才该轮到它
		{ID: 300, ModelNameID: 1, UpstreamID: 30, Priority: 2, Weight: 100, Enabled: true},
	}
	snap := BuildSnapshot([]*model.ModelName{mn}, ups, routes)
	hv := newFakeHealth()

	// 连取两次，必须把优先级 1 的两条都用上，一次都不能落到 300
	first, err := Select(snap, hv, "m", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Select(snap, hv, "m", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64]bool{first.Route.ID: true, second.Route.ID: true}
	if !got[100] || !got[200] {
		t.Errorf("应把同优先级的 100 与 200 都用上，得到 %d 与 %d",
			first.Route.ID, second.Route.ID)
	}

	// 这时优先级 1 才算满，第三次应溢出
	third, err := Select(snap, hv, "m", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if third.Route.ID != 300 {
		t.Errorf("优先级 1 全满后应溢出到 300，得到 %d", third.Route.ID)
	}
}

// 桶内所有 Route 都满时才报错，且错误要能让人看懂是并发上限而不是站挂了。
func TestSelect_AllAtLimit(t *testing.T) {
	snap := basicSnapshot()
	for _, r := range snap.RoutesByModelName[1] {
		r.MaxConcurrency = 1
	}
	hv := newFakeHealth()

	for i := 0; i < 3; i++ {
		if _, err := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic); err != nil {
			t.Fatalf("前 3 个请求应各占一条 Route，第 %d 个失败：%v", i, err)
		}
	}
	_, err := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
	if !errors.Is(err, ErrNoRouteAvailable) {
		t.Fatalf("全部达上限应返回 ErrNoRouteAvailable，得到 %v", err)
	}
	if !strings.Contains(err.Error(), "并发上限") {
		t.Errorf("错误信息应指明是并发上限，得到：%v", err)
	}
}

// 手动停用的 Route 与 Upstream 都不参与选路。
func TestSelect_RespectsDisabled(t *testing.T) {
	snap := basicSnapshot()
	hv := newFakeHealth()

	snap.RoutesByModelName[1][0].Enabled = false
	if c, _ := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic); c.Route.ID != 200 {
		t.Errorf("Route 停用应跳过，得到 %d", c.Route.ID)
	}

	// 站停用是常见的临时下线方式，也必须生效
	snap.Upstreams[20].Enabled = false
	if c, _ := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic); c.Route.ID != 300 {
		t.Errorf("Upstream 停用应跳过其 Route，得到 %d", c.Route.ID)
	}
}

// 同优先级按 weight 加权随机。用大样本验证分布大致符合权重比例。
func TestSelect_WeightedRandomWithinBucket(t *testing.T) {
	mn := &model.ModelName{ID: 1, Name: "m", Protocol: model.ProtoAnthropic,
		MatchMode: model.MatchExact, Enabled: true}
	ups := []*model.Upstream{
		{ID: 10, Enabled: true}, {ID: 20, Enabled: true},
	}
	routes := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 300, Enabled: true},
		{ID: 200, ModelNameID: 1, UpstreamID: 20, Priority: 1, Weight: 100, Enabled: true},
	}
	snap := BuildSnapshot([]*model.ModelName{mn}, ups, routes)
	hv := newFakeHealth()

	counts := map[int64]int{}
	const n = 4000
	for i := 0; i < n; i++ {
		c, err := Select(snap, hv, "m", model.ProtoAnthropic)
		if err != nil {
			t.Fatal(err)
		}
		counts[c.Route.ID]++
	}
	// 期望 3:1。给足容差，只验证「大致按权重」而非精确比例
	ratio := float64(counts[100]) / float64(counts[200])
	if ratio < 2.0 || ratio > 4.5 {
		t.Errorf("权重 300:100 的实际比例应接近 3，得到 %.2f（%d vs %d）",
			ratio, counts[100], counts[200])
	}
	if counts[200] == 0 {
		t.Error("低权重的 Route 也应偶尔被选中")
	}
}

// 前缀匹配必须最长优先，否则结果取决于遍历顺序，行为随机。
func TestMatchModelName_LongestPrefixWins(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "claude", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
		{ID: 2, Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
		{ID: 3, Name: "claude-opus", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
	}
	snap := BuildSnapshot(mns, nil, nil)

	got, err := MatchModelName(snap, "claude-opus-5-thinking", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 2 {
		t.Errorf("应命中最长前缀 claude-opus-5（ID 2），得到 ID %d (%q)", got.ID, got.Name)
	}

	// 多跑几次确认稳定（防止 map 遍历顺序影响结果）
	for i := 0; i < 20; i++ {
		if g, _ := MatchModelName(snap, "claude-opus-5-thinking", model.ProtoAnthropic); g.ID != 2 {
			t.Fatalf("第 %d 次匹配结果不稳定：得到 ID %d", i, g.ID)
		}
	}
}

// 精确匹配优先于前缀匹配。
func TestMatchModelName_ExactBeatsPrefix(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
		{ID: 2, Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, Enabled: true},
	}
	snap := BuildSnapshot(mns, nil, nil)
	got, err := MatchModelName(snap, "claude-opus-5", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 2 {
		t.Errorf("精确匹配应优先，得到 ID %d", got.ID)
	}
}

// §6.4：精确 Route 因 config_error / exclude 不合格时，仍应选健康前缀；
// 精确健康时仍优于前缀。selectFor 把 config_error 放进 exclude 再调
// SelectExcluding，故此处用 exclude 模拟。
func TestSelectExcluding_ExcludedExactFallsToPrefix(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, Enabled: true},
		{ID: 2, Name: "claude-", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
	}
	ups := []*model.Upstream{
		{ID: 10, Name: "exact-up", Enabled: true},
		{ID: 20, Name: "prefix-up", Enabled: true},
	}
	rts := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 1, Enabled: true},
		{ID: 200, ModelNameID: 2, UpstreamID: 20, Priority: 1, Weight: 1, Enabled: true},
	}
	snap := BuildSnapshot(mns, ups, rts)
	hv := newFakeHealth()

	// 精确 Route 被排除（config_error）→ 健康前缀。
	c, err := SelectExcluding(snap, hv, "claude-opus-5", model.ProtoAnthropic,
		map[int64]bool{100: true})
	if err != nil {
		t.Fatalf("excluded exact should fall to prefix: %v", err)
	}
	if c.Route.ID != 200 || c.ModelName.ID != 2 {
		t.Fatalf("want prefix route 200 / ModelName 2, got route %d ModelName %d",
			c.Route.ID, c.ModelName.ID)
	}
	c.Release()

	// 精确健康 → 仍选精确，不抢前缀。
	c, err = SelectExcluding(snap, hv, "claude-opus-5", model.ProtoAnthropic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Route.ID != 100 || c.ModelName.ID != 1 {
		t.Fatalf("healthy exact must beat prefix, got route %d ModelName %d",
			c.Route.ID, c.ModelName.ID)
	}
	c.Release()
}

// 不合格的较短前缀不得压过健康的更长前缀；名称已命中时也不回落兜底。
func TestSelectExcluding_ExcludedPrefixFallsToLongerNotFallback(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
		{ID: 2, Name: "claude-", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
		{ID: 9, Name: "catch-all", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, IsFallback: true, Enabled: true},
	}
	ups := []*model.Upstream{
		{ID: 10, Name: "long", Enabled: true},
		{ID: 20, Name: "short", Enabled: true},
		{ID: 90, Name: "fb", Enabled: true},
	}
	rts := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 1, Enabled: true},
		{ID: 200, ModelNameID: 2, UpstreamID: 20, Priority: 1, Weight: 1, Enabled: true},
		{ID: 900, ModelNameID: 9, UpstreamID: 90, Priority: 1, Weight: 1, Enabled: true},
	}
	snap := BuildSnapshot(mns, ups, rts)
	hv := newFakeHealth()

	// 最长前缀 Route 被排除 → 次长前缀，不是兜底。
	c, err := SelectExcluding(snap, hv, "claude-opus-5-thinking", model.ProtoAnthropic,
		map[int64]bool{100: true})
	if err != nil {
		t.Fatalf("excluded longest prefix should fall to shorter prefix: %v", err)
	}
	if c.Route.ID != 200 || c.ModelName.ID != 2 {
		t.Fatalf("want shorter prefix route 200, got route %d ModelName %d",
			c.Route.ID, c.ModelName.ID)
	}
	c.Release()

	// 名称命中的前缀全排除 → ErrNoRouteAvailable，不吃兜底。
	_, err = SelectExcluding(snap, hv, "claude-opus-5-thinking", model.ProtoAnthropic,
		map[int64]bool{100: true, 200: true})
	if !errors.Is(err, ErrNoRouteAvailable) {
		t.Fatalf("name-matched but all excluded must not use fallback, got %v", err)
	}
}

func TestMatchModelName_Fallback(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, Enabled: true},
		{ID: 9, Name: "catch-all", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, IsFallback: true, Enabled: true},
	}
	snap := BuildSnapshot(mns, nil, nil)

	// 未匹配 → 兜底（这是 haiku 这类小模型的接入方式）
	got, err := MatchModelName(snap, "claude-haiku-4-5-20251001", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 9 {
		t.Errorf("未匹配应落到兜底，得到 ID %d", got.ID)
	}

	// 有精确匹配时不走兜底
	if got, _ = MatchModelName(snap, "claude-opus-5", model.ProtoAnthropic); got.ID != 1 {
		t.Errorf("精确匹配存在时不应走兜底，得到 ID %d", got.ID)
	}
}

// 兜底是**每协议**一个，不是全局一个。
//
// 全局唯一的话，配了 anthropic 兜底之后，/v1/chat/completions 与
// /v1/responses 上任何未配置的模型都会撞上「协议不一致」的 400 ——
// 而用户的意图明明是「都走兜底」。schema 的部分唯一索引也按协议建。
func TestMatchModelName_FallbackPerProtocol(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "anthropic-fb", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, IsFallback: true, Enabled: true},
		{ID: 2, Name: "chat-fb", Protocol: model.ProtoOpenAIChat,
			MatchMode: model.MatchExact, IsFallback: true, Enabled: true},
	}
	snap := BuildSnapshot(mns, nil, nil)

	cases := []struct {
		proto  model.Protocol
		wantID int64
	}{
		{model.ProtoAnthropic, 1},
		{model.ProtoOpenAIChat, 2},
	}
	for _, c := range cases {
		t.Run(string(c.proto), func(t *testing.T) {
			got, err := MatchModelName(snap, "never-configured", c.proto)
			if err != nil {
				t.Fatalf("应落到该协议的兜底，得到 %v", err)
			}
			if got.ID != c.wantID {
				t.Errorf("应命中 ID %d，得到 %d", c.wantID, got.ID)
			}
		})
	}

	// 没有对应协议的兜底时，报「找不到」而不是拿别的协议的兜底顶上 ——
	// 顶上去只会把 Anthropic 的 body 发到 chat/completions，得到一个
	// 更难理解的上游 400。
	if _, err := MatchModelName(snap, "x", model.ProtoOpenAIResponses); !errors.Is(err, ErrModelNotFound) {
		t.Errorf("无该协议的兜底时应返回 ErrModelNotFound，得到 %v", err)
	}
}

// 端到端：兜底必须能真的转发出去，而不是止步于协议校验。
func TestSelect_FallbackWorksOnEachEndpoint(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "a-fb", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, IsFallback: true, Enabled: true},
		{ID: 2, Name: "c-fb", Protocol: model.ProtoOpenAIChat,
			MatchMode: model.MatchExact, IsFallback: true, Enabled: true},
	}
	ups := []*model.Upstream{{ID: 10, Name: "s", Enabled: true}}
	rts := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 1, Enabled: true},
		{ID: 200, ModelNameID: 2, UpstreamID: 10, Priority: 1, Weight: 1, Enabled: true},
	}
	snap := BuildSnapshot(mns, ups, rts)
	hv := newFakeHealth()

	for _, c := range []struct {
		proto   model.Protocol
		wantRte int64
	}{
		{model.ProtoAnthropic, 100},
		{model.ProtoOpenAIChat, 200},
	} {
		t.Run(string(c.proto), func(t *testing.T) {
			cand, err := Select(snap, hv, "totally-unconfigured", c.proto)
			if err != nil {
				t.Fatalf("兜底应可用，得到 %v", err)
			}
			if cand.Route.ID != c.wantRte {
				t.Errorf("应走 Route %d，得到 %d", c.wantRte, cand.Route.ID)
			}
		})
	}
}

func TestMatchModelName_NotFound(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, Enabled: true},
	}
	snap := BuildSnapshot(mns, nil, nil)

	for _, in := range []string{"gpt-5.6-sol", "", "claude-opus"} {
		if _, err := MatchModelName(snap, in, model.ProtoAnthropic); !errors.Is(err, ErrModelNotFound) {
			t.Errorf("%q 应返回 ErrModelNotFound，得到 %v", in, err)
		}
	}
}

// 空前缀绝不能当「匹配一切」：strings.HasPrefix(s, "") 对任意 s 为 true。
// Validate 会拒写入，但坏行仍可能进快照；匹配器必须自行跳过。
func TestMatchModelName_EmptyPrefixDoesNotMatchAll(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
		{ID: 2, Name: "   ", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
	}
	ups := []*model.Upstream{{ID: 10, Name: "s", Enabled: true}}
	rts := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 1, Enabled: true},
		{ID: 200, ModelNameID: 2, UpstreamID: 10, Priority: 1, Weight: 1, Enabled: true},
	}
	snap := BuildSnapshot(mns, ups, rts)

	if _, err := MatchModelName(snap, "claude-opus", model.ProtoAnthropic); !errors.Is(err, ErrModelNotFound) {
		t.Fatalf("空前缀不得匹配 claude-opus，得到 %v", err)
	}
	// Select 也不得给出 Candidate —— 否则会出网上游（零上游调用）。
	if cand, err := Select(snap, newFakeHealth(), "claude-opus", model.ProtoAnthropic); !errors.Is(err, ErrModelNotFound) {
		t.Fatalf("空前缀 Select 应失败且零上游，得到 cand=%v err=%v", cand, err)
	}
}

// 停用的 ModelName 不参与匹配，包括不能当兜底。
func TestMatchModelName_SkipsDisabled(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "m", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, Enabled: false},
		{ID: 2, Name: "fb", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, IsFallback: true, Enabled: false},
	}
	snap := BuildSnapshot(mns, nil, nil)
	// 点名停用精确名 → ErrNoRouteAvailable（不是「从未配置」的 404）。
	if _, err := MatchModelName(snap, "m", model.ProtoAnthropic); !errors.Is(err, ErrNoRouteAvailable) {
		t.Errorf("停用的精确名应回 ErrNoRouteAvailable，得到 %v", err)
	}
}

// 已配置但停用的精确名不得落到启用的前缀或兜底（否则点名模型被静默换站）。
// 未配置名仍可走兜底；启用精确名仍优先于前缀与兜底。
func TestMatchModelName_DisabledExactBlocksPrefixAndFallback(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, Enabled: false},
		{ID: 2, Name: "claude-", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
		{ID: 9, Name: "catch-all", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, IsFallback: true, Enabled: true},
	}
	ups := []*model.Upstream{
		{ID: 20, Name: "prefix-up", Enabled: true},
		{ID: 90, Name: "fb-up", Enabled: true},
	}
	rts := []*model.Route{
		{ID: 200, ModelNameID: 2, UpstreamID: 20, Priority: 1, Weight: 1, Enabled: true},
		{ID: 900, ModelNameID: 9, UpstreamID: 90, Priority: 1, Weight: 1, Enabled: true},
	}
	snap := BuildSnapshot(mns, ups, rts)
	hv := newFakeHealth()

	if _, err := MatchModelName(snap, "claude-opus-5", model.ProtoAnthropic); !errors.Is(err, ErrNoRouteAvailable) {
		t.Fatalf("disabled exact must not match prefix/fallback, got %v", err)
	}
	if _, err := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic); !errors.Is(err, ErrNoRouteAvailable) {
		t.Fatalf("Select disabled exact must not use prefix/fallback, got %v", err)
	}

	// 从未配置的名字仍可走兜底。
	got, err := MatchModelName(snap, "never-configured", model.ProtoAnthropic)
	if err != nil || got.ID != 9 {
		t.Fatalf("unknown name should use fallback, got %v err=%v", got, err)
	}
	c, err := Select(snap, hv, "never-configured", model.ProtoAnthropic)
	if err != nil || c.Route.ID != 900 {
		t.Fatalf("unknown Select should use fallback route 900, got %+v err=%v", c, err)
	}
	c.Release()
}

func TestSelect_EnabledExactStillBeatsPrefixAndFallback(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, Enabled: true},
		{ID: 2, Name: "claude-", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchPrefix, Enabled: true},
		{ID: 9, Name: "catch-all", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, IsFallback: true, Enabled: true},
	}
	ups := []*model.Upstream{
		{ID: 10, Name: "exact-up", Enabled: true},
		{ID: 20, Name: "prefix-up", Enabled: true},
		{ID: 90, Name: "fb-up", Enabled: true},
	}
	rts := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 1, Enabled: true},
		{ID: 200, ModelNameID: 2, UpstreamID: 20, Priority: 1, Weight: 1, Enabled: true},
		{ID: 900, ModelNameID: 9, UpstreamID: 90, Priority: 1, Weight: 1, Enabled: true},
	}
	snap := BuildSnapshot(mns, ups, rts)
	c, err := Select(snap, newFakeHealth(), "claude-opus-5", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if c.Route.ID != 100 || c.ModelName.ID != 1 {
		t.Fatalf("enabled exact must win, got route %d ModelName %d", c.Route.ID, c.ModelName.ID)
	}
	c.Release()
}

// 协议不一致必须明确报错，而不是把 Anthropic 的 body 发到 chat/completions。
func TestSelect_ProtocolMismatch(t *testing.T) {
	snap := basicSnapshot()
	hv := newFakeHealth()

	_, err := Select(snap, hv, "claude-opus-5", model.ProtoOpenAIChat)
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("协议不一致应返回 ErrProtocolMismatch，得到 %v", err)
	}
	// 错误信息要同时给出两边，否则不知道该改哪一侧
	if !strings.Contains(err.Error(), "openai-chat") || !strings.Contains(err.Error(), "anthropic") {
		t.Errorf("错误信息应同时说明端点协议与配置协议，得到：%v", err)
	}
}

func TestSelect_NoRoutesBound(t *testing.T) {
	mn := &model.ModelName{ID: 1, Name: "m", Protocol: model.ProtoAnthropic,
		MatchMode: model.MatchExact, Enabled: true}
	snap := BuildSnapshot([]*model.ModelName{mn}, nil, nil)

	_, err := Select(snap, newFakeHealth(), "m", model.ProtoAnthropic)
	if !errors.Is(err, ErrNoRouteAvailable) {
		t.Fatalf("未绑定 Route 应返回 ErrNoRouteAvailable，得到 %v", err)
	}
	if !strings.Contains(err.Error(), "没有绑定") {
		t.Errorf("错误信息应说明未绑定 Route，得到：%v", err)
	}
}

// Route 指向已删除的 Upstream 时，应跳过它而不是崩，让其余 Route 继续服务。
func TestSelect_ToleratesDanglingUpstream(t *testing.T) {
	snap := basicSnapshot()
	delete(snap.Upstreams, 10) // 模拟配置不一致
	hv := newFakeHealth()

	c, err := Select(snap, hv, "claude-opus-5", model.ProtoAnthropic)
	if err != nil {
		t.Fatalf("应跳过悬挂 Route 并选下一个，得到错误 %v", err)
	}
	if c.Route.ID != 200 {
		t.Errorf("应选 200，得到 %d", c.Route.ID)
	}
}

// 半开放行（§4.4c）：全部 dead 时按优先级给出候选，供试探一次。
func TestDeadRoutesFor(t *testing.T) {
	snap := basicSnapshot()
	hv := newFakeHealth()
	hv.states[100] = model.StateDead
	hv.states[200] = model.StateDead
	hv.states[300] = model.StateDead

	mn := snap.ModelNames[0]
	dead := DeadRoutesFor(snap, hv, mn)
	if len(dead) != 3 {
		t.Fatalf("应返回 3 个 dead Route，得到 %d", len(dead))
	}
	// 必须按优先级升序，半开要试探优先级最高的
	if dead[0].ID != 100 || dead[2].ID != 300 {
		t.Errorf("应按优先级升序返回，得到 %d,%d,%d", dead[0].ID, dead[1].ID, dead[2].ID)
	}

	// 停用的不算候选 —— 手动停用是明确意图，半开不该绕过它
	snap.RoutesByModelName[1][0].Enabled = false
	if dead = DeadRoutesFor(snap, hv, mn); len(dead) != 2 || dead[0].ID != 200 {
		t.Errorf("停用的 Route 不应作为半开候选，得到 %d 个", len(dead))
	}
}

func TestSelect_ReturnsFullCandidate(t *testing.T) {
	snap := basicSnapshot()
	c, err := Select(snap, newFakeHealth(), "claude-opus-5", model.ProtoAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if c.Route == nil || c.Upstream == nil || c.ModelName == nil {
		t.Fatal("Candidate 三个字段都应填充")
	}
	if c.Upstream.ID != c.Route.UpstreamID {
		t.Error("Candidate.Upstream 与 Route.UpstreamID 不一致")
	}
	if c.ModelName.Name != "claude-opus-5" {
		t.Errorf("ModelName 不正确：%q", c.ModelName.Name)
	}
}

// ── SelectExcluding：重试换站（§3.5）────────────────────────

// 排除已试过的 Route 后，应按优先级顺序换到下一个。
func TestSelectExcluding_SkipsTriedRoutes(t *testing.T) {
	snap := basicSnapshot()
	hv := newFakeHealth()

	// 没有排除项时行为与 Select 一致 —— 这条保证既有调用方不受影响。
	c, err := SelectExcluding(snap, hv, "claude-opus-5", model.ProtoAnthropic, nil)
	if err != nil || c.Route.ID != 100 {
		t.Fatalf("空排除集应选优先级最高的 100，得到 %v / %v", c, err)
	}
	c.Release()

	// 试过 100 之后应换到 200，而不是重复 100 或直接跳到 300。
	c, err = SelectExcluding(snap, hv, "claude-opus-5", model.ProtoAnthropic,
		map[int64]bool{100: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.Route.ID != 200 {
		t.Errorf("排除 100 后应选 200（按优先级顺序），得到 %d", c.Route.ID)
	}
	c.Release()

	// 试过前两个，只剩 300。
	c, err = SelectExcluding(snap, hv, "claude-opus-5", model.ProtoAnthropic,
		map[int64]bool{100: true, 200: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.Route.ID != 300 {
		t.Errorf("排除 100/200 后应选 300，得到 %d", c.Route.ID)
	}
	c.Release()
}

// 全部试过之后必须给出「已试过」的错误，而不是假装还有得选。
//
// 原因写进错误里很重要：「3 个 Route 都试过了」与「3 个 Route 都 dead」
// 是完全不同的处境 —— 后者该去看健康状态，前者该去看那几次尝试各自
// 失败在哪。混成一句话会把人引向错误的排查方向。
func TestSelectExcluding_AllTriedReportsWhy(t *testing.T) {
	snap := basicSnapshot()
	_, err := SelectExcluding(snap, newFakeHealth(), "claude-opus-5",
		model.ProtoAnthropic, map[int64]bool{100: true, 200: true, 300: true})

	if !errors.Is(err, ErrNoRouteAvailable) {
		t.Fatalf("全部试过应回 ErrNoRouteAvailable，得到 %v", err)
	}
	if !strings.Contains(err.Error(), "已试过") {
		t.Errorf("错误信息应说明是「本次已试过」而不是「都挂了」，得到：%v", err)
	}
}

// 排除集不该影响健康状态的判定 —— 一个被排除的 Route 仍然是「可用」的，
// 只是这一次请求不再选它。下一次请求必须能重新选到它。
//
// 这条防的是「把重试历史记在 selector 里」那种实现：一次失败之后
// 某个站就再也选不到了，而且不会自愈。
func TestSelectExcluding_DoesNotPersistAcrossCalls(t *testing.T) {
	snap := basicSnapshot()
	hv := newFakeHealth()

	c, err := SelectExcluding(snap, hv, "claude-opus-5", model.ProtoAnthropic,
		map[int64]bool{100: true})
	if err != nil {
		t.Fatal(err)
	}
	c.Release()

	// 新的一次请求（空排除集）必须又能选到 100。
	c, err = SelectExcluding(snap, hv, "claude-opus-5", model.ProtoAnthropic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Route.ID != 100 {
		t.Errorf("排除集不该跨请求残留，新请求应重新选到 100，得到 %d", c.Route.ID)
	}
	c.Release()
}

// 两个接近 int 上限的 weight 若用 int 累加会绕回成负/零 total，
// 旧实现会总是返回下标 0（或 IntN panic）。这里确认不再如此。
func TestWeightedPick_MaxIntWeightsDoNotCollapseToFirst(t *testing.T) {
	rs := []*model.Route{
		{ID: 1, Weight: math.MaxInt},
		{ID: 2, Weight: math.MaxInt},
	}
	counts := [2]int{}
	const n = 200
	for i := 0; i < n; i++ {
		idx := weightedPick(rs)
		if idx < 0 || idx > 1 {
			t.Fatalf("下标越界: %d", idx)
		}
		counts[idx]++
	}
	if counts[0] == 0 || counts[1] == 0 {
		t.Fatalf("MaxInt 权重不应塌缩到总选第一路；counts=%v", counts)
	}
}

// 小权重求和与缩放不依赖全局 RNG：300:100 在 int64 上应原样累加且无需右移。
func TestWeightTotal_SmallWeightsUnscaled(t *testing.T) {
	rs := []*model.Route{
		{Weight: 300},
		{Weight: 100},
	}
	total, shift, ok := weightTotal(rs)
	if !ok {
		t.Fatal("小权重求和不应失败")
	}
	if shift != 0 {
		t.Errorf("小权重不应右移，shift=%d", shift)
	}
	if total != 400 {
		t.Errorf("total 应为 400，得到 %d", total)
	}
	if scaledWeight(300, 0) != 300 || scaledWeight(100, 0) != 100 {
		t.Errorf("未缩放时权重应保持原值")
	}
}

// MaxInt+MaxInt 在 int64 上也会溢出；缩放后两边仍为正且相等，比例可保留。
func TestWeightTotal_MaxIntPairScales(t *testing.T) {
	rs := []*model.Route{
		{Weight: math.MaxInt},
		{Weight: math.MaxInt},
	}
	total, shift, ok := weightTotal(rs)
	if !ok {
		t.Fatal("MaxInt 对应能通过缩放求和")
	}
	if shift == 0 && total <= 0 {
		t.Fatal("未缩放时 total 不应为负/零（若平台 int 已是 64 位则必须右移）")
	}
	w0 := scaledWeight(math.MaxInt, shift)
	w1 := scaledWeight(math.MaxInt, shift)
	if w0 <= 0 || w1 <= 0 {
		t.Fatalf("缩放后权重须为正: %d, %d (shift=%d)", w0, w1, shift)
	}
	if w0 != w1 {
		t.Fatalf("两路 MaxInt 缩放后应相等: %d vs %d", w0, w1)
	}
	if total != w0+w1 {
		t.Fatalf("total=%d 应等于 %d+%d", total, w0, w1)
	}
}
