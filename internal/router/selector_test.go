package router

import (
	"errors"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// fakeHealth 让测试能精确控制每个 Route 的状态。
type fakeHealth struct {
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
func (f *fakeHealth) InFlight(id int64) int     { return f.inflight[id] }
func (f *fakeHealth) CoolingDown(id int64) bool { return f.cooling[id] }

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

	got, err := MatchModelName(snap, "claude-opus-5-thinking")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 2 {
		t.Errorf("应命中最长前缀 claude-opus-5（ID 2），得到 ID %d (%q)", got.ID, got.Name)
	}

	// 多跑几次确认稳定（防止 map 遍历顺序影响结果）
	for i := 0; i < 20; i++ {
		if g, _ := MatchModelName(snap, "claude-opus-5-thinking"); g.ID != 2 {
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
	got, err := MatchModelName(snap, "claude-opus-5")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 2 {
		t.Errorf("精确匹配应优先，得到 ID %d", got.ID)
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
	got, err := MatchModelName(snap, "claude-haiku-4-5-20251001")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 9 {
		t.Errorf("未匹配应落到兜底，得到 ID %d", got.ID)
	}

	// 有精确匹配时不走兜底
	if got, _ = MatchModelName(snap, "claude-opus-5"); got.ID != 1 {
		t.Errorf("精确匹配存在时不应走兜底，得到 ID %d", got.ID)
	}
}

func TestMatchModelName_NotFound(t *testing.T) {
	mns := []*model.ModelName{
		{ID: 1, Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, Enabled: true},
	}
	snap := BuildSnapshot(mns, nil, nil)

	for _, in := range []string{"gpt-5.6-sol", "", "claude-opus"} {
		if _, err := MatchModelName(snap, in); !errors.Is(err, ErrModelNotFound) {
			t.Errorf("%q 应返回 ErrModelNotFound，得到 %v", in, err)
		}
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
	if _, err := MatchModelName(snap, "m"); !errors.Is(err, ErrModelNotFound) {
		t.Errorf("停用的 ModelName 不应被匹配，得到 %v", err)
	}
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
