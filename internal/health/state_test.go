package health

import (
	"errors"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// fakeSettings 让测试能改阈值。
type fakeSettings struct {
	s   model.Settings
	err error
}

func (f *fakeSettings) Settings() (model.Settings, error) { return f.s, f.err }

// newTestTracker 返回一个时钟可控的 Tracker。
//
// 必须能控制时钟：冷却、探活间隔、piggyback 都是时间条件，
// 用真实时钟测就只能靠 Sleep —— 那会让测试要么慢得没人跑，要么在
// CI 的负载下随机失败。
func newTestTracker(t *testing.T) (*Tracker, *fakeSettings, *time.Time) {
	t.Helper()
	fs := &fakeSettings{s: model.DefaultSettings()}
	tr := NewTracker(fs)
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	tr.now = func() time.Time { return now }
	return tr, fs, &now
}

func report(tr *Tracker, id int64, v Verdict, src Source) bool {
	return tr.Report(Report{RouteID: id, Verdict: v, Source: src})
}

// ── §4.3 三类失败的动作不同 ──────────────────────────────

// 致命错误立即判死，不等累计。401 重试一万次还是 401，
// 让它留在池子里只会让每个请求都撞一次墙。
func TestReport_FatalIsImmediatelyDead(t *testing.T) {
	tr, _, _ := newTestTracker(t)

	changed := tr.Report(Report{
		RouteID: 1, Verdict: VerdictFatal, Source: SourceL2,
		Err: errors.New("401 unauthorized"),
	})
	if !changed {
		t.Error("状态从 unknown 变 dead，changed 应为 true")
	}
	if got := tr.State(1); got != model.StateDead {
		t.Errorf("致命错误应立即 dead，得到 %s", got)
	}

	st := tr.Status(1)
	if st.Reason != "fatal" {
		t.Errorf("Reason 应为 fatal（UI 据此显示「配置错误」而非「站挂了」），得到 %q", st.Reason)
	}
	if st.LastError != "401 unauthorized" {
		t.Errorf("失败原因应原样保留，得到 %q", st.LastError)
	}
}

// 服务不可用要累计到阈值。公益站抖动是常态，一次失败就判死会让池子反复空掉。
func TestReport_UnavailableAccumulatesToThreshold(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.FailThreshold = 2

	if report(tr, 1, VerdictUnavailable, SourceL2) {
		t.Error("第 1 次失败还没到阈值，状态不该变")
	}
	if got := tr.State(1); got != model.StateUnknown {
		t.Errorf("第 1 次失败后应仍是 unknown（可用），得到 %s", got)
	}

	if !report(tr, 1, VerdictUnavailable, SourceL2) {
		t.Error("第 2 次失败达到阈值，状态应变为 dead")
	}
	if got := tr.State(1); got != model.StateDead {
		t.Errorf("达到阈值应 dead，得到 %s", got)
	}
}

// 一次成功清零失败计数。否则「失败-成功-失败」的抖动会被当成连续两次失败，
// 把一个大体可用的站判死。
func TestReport_SuccessResetsFailureCount(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.FailThreshold = 2

	report(tr, 1, VerdictUnavailable, SourceL2)
	report(tr, 1, VerdictOK, SourceL2)
	report(tr, 1, VerdictUnavailable, SourceL2)

	if got := tr.State(1); got == model.StateDead {
		t.Error("中间成功过一次，不该被判死（失败计数应已清零）")
	}
	if n := tr.Status(1).ConsecutiveFail; n != 1 {
		t.Errorf("失败计数应为 1，得到 %d", n)
	}
}

// 429 冷却但不判死，也不计失败。把限流站判死等于因为它「太受欢迎」而拉黑它。
func TestReport_RateLimitedCoolsDownWithoutDying(t *testing.T) {
	tr, fs, now := newTestTracker(t)
	fs.s.CooldownSec = 60
	fs.s.FailThreshold = 2

	// 先攒一次真实失败，验证 429 会把它清零
	report(tr, 1, VerdictUnavailable, SourceL2)

	tr.Report(Report{RouteID: 1, Verdict: VerdictRateLimited, Source: SourceReal})
	if got := tr.State(1); got == model.StateDead {
		t.Error("429 不该判死")
	}
	if !tr.CoolingDown(1) {
		t.Error("429 后应进入冷却")
	}
	if n := tr.Status(1).ConsecutiveFail; n != 0 {
		t.Errorf("429 不计入失败且应清零已有计数，得到 %d", n)
	}

	*now = now.Add(59 * time.Second)
	if !tr.CoolingDown(1) {
		t.Error("59 秒时仍应在冷却中")
	}
	*now = now.Add(2 * time.Second)
	if tr.CoolingDown(1) {
		t.Error("超过 60 秒后冷却应结束")
	}
}

// 上游给了 Retry-After 就尊重它（§4.3）。自作主张用默认值的话，
// 站说「等 300 秒」我们 60 秒就重试，只会再吃一个 429。
func TestReport_RateLimitedRespectsRetryAfter(t *testing.T) {
	tr, fs, now := newTestTracker(t)
	fs.s.CooldownSec = 60

	tr.Report(Report{
		RouteID: 1, Verdict: VerdictRateLimited, Source: SourceReal,
		RetryAfter: 300 * time.Second,
	})

	*now = now.Add(120 * time.Second)
	if !tr.CoolingDown(1) {
		t.Error("上游要求等 300 秒，120 秒时不该结束冷却")
	}
	*now = now.Add(200 * time.Second)
	if tr.CoolingDown(1) {
		t.Error("超过 300 秒后应结束冷却")
	}
}

// 成功即解除冷却：上游明确回了正常响应，没理由继续排除它。
func TestReport_SuccessClearsCooldown(t *testing.T) {
	tr, _, _ := newTestTracker(t)

	tr.Report(Report{RouteID: 1, Verdict: VerdictRateLimited, Source: SourceL2})
	if !tr.CoolingDown(1) {
		t.Fatal("前置条件：应在冷却中")
	}
	report(tr, 1, VerdictOK, SourceL2)
	if tr.CoolingDown(1) {
		t.Error("成功后应立即解除冷却")
	}
}

// VerdictIgnore 完全不动状态机。这条不成立的话，用户按 Ctrl-C
// 取消长对话就会给站记一次失败 —— 取消得够频繁就能把所有好站判死。
func TestReport_IgnoreDoesNotTouchState(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.FailThreshold = 2

	report(tr, 1, VerdictUnavailable, SourceReal)
	before := tr.Status(1)

	for i := 0; i < 10; i++ {
		if report(tr, 1, VerdictIgnore, SourceReal) {
			t.Fatal("Ignore 不该引起状态变化")
		}
	}

	after := tr.Status(1)
	if after.ConsecutiveFail != before.ConsecutiveFail {
		t.Errorf("Ignore 不该动失败计数：%d → %d", before.ConsecutiveFail, after.ConsecutiveFail)
	}
	if after.State != before.State {
		t.Errorf("Ignore 不该改状态：%s → %s", before.State, after.State)
	}
}

// ── §4.4 恢复判定 ────────────────────────────────────────

// 死站首次探通就转 unknown（可用），不必等第二次。
// 让恢复的站空等一个探活周期，正是这个项目要解决的痛点。
func TestReport_DeadRouteRecoversToUnknownOnFirstSuccess(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.FailThreshold = 1
	fs.s.OKThreshold = 2

	report(tr, 1, VerdictUnavailable, SourceL2)
	if tr.State(1) != model.StateDead {
		t.Fatal("前置条件：应为 dead")
	}

	report(tr, 1, VerdictOK, SourceL2)
	if got := tr.State(1); got != model.StateUnknown {
		t.Errorf("死站首次探通应转 unknown（立即可用），得到 %s", got)
	}

	report(tr, 1, VerdictOK, SourceL2)
	if got := tr.State(1); got != model.StateAlive {
		t.Errorf("连续 2 次成功应升 alive，得到 %s", got)
	}
}

// unknown 期间真实请求成功 → 直接升 alive，不用等够 OKThreshold。
// 真实请求带着完整上下文和工具定义都通过了，比 `1+1=?` 有力得多。
func TestReport_RealSuccessPromotesUnknownToAlive(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.OKThreshold = 5 // 故意调高，验证真实请求能绕过它

	if !report(tr, 1, VerdictOK, SourceReal) {
		t.Error("unknown → alive 是状态变化")
	}
	if got := tr.State(1); got != model.StateAlive {
		t.Errorf("真实请求成功应让 unknown 直接升 alive，得到 %s", got)
	}
}

// 但**死站**的真实请求成功只能升到 unknown，不能直接 alive。
// 半开放行（§4.4c）会让真实流量打到死站上，一次成功就宣布痊愈太乐观了。
func TestReport_RealSuccessOnDeadOnlyReachesUnknown(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.FailThreshold = 1
	fs.s.OKThreshold = 2

	report(tr, 1, VerdictUnavailable, SourceL2)
	report(tr, 1, VerdictOK, SourceReal)

	if got := tr.State(1); got != model.StateUnknown {
		t.Errorf("半开成功应转 unknown 而非直接 alive，得到 %s", got)
	}
}

// 状态没变时 changed 必须是 false，否则调度器每 20 秒就写一次库、
// 打一行「still alive」，日志和磁盘都会被刷满。
func TestReport_ChangedIsFalseWhenStateStable(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.OKThreshold = 1

	report(tr, 1, VerdictOK, SourceL2) // unknown → alive
	for i := 0; i < 5; i++ {
		if report(tr, 1, VerdictOK, SourceL2) {
			t.Fatal("已经是 alive，重复成功不该报告状态变化")
		}
	}
}

// ── §4.6 调度：间隔、预占、piggyback ──────────────────────

// unknown 立即探活：重启后全部是 unknown，要尽快收敛到真实状态。
func TestClaim_UnknownProbesImmediately(t *testing.T) {
	tr, _, _ := newTestTracker(t)

	if !tr.ClaimL1(1) {
		t.Error("unknown 的 L1 应立即到期")
	}
	if !tr.ClaimL2(1) {
		t.Error("unknown 的 L2 应立即到期")
	}
	// unknown 的间隔是 0，所以下一个 tick 仍然到期 —— 这是有意的，
	// 状态会在首次探活结果回来后立刻变成 alive/dead，自然就不再是 0 了。
}

// Claim 必须原子：到期判定与预占是一个操作。
// 拆开的话，慢探活（L1 给了 25 秒）跑到一半时下个 tick 会再次判定到期，
// 同一个 Route 被同时探两次，请求翻倍且判定互相覆盖。
func TestClaim_IsAtomicAndPreventsDoubleProbe(t *testing.T) {
	tr, fs, now := newTestTracker(t)
	fs.s.OKThreshold = 1
	fs.s.L1IntervalAliveSec = 60

	report(tr, 1, VerdictOK, SourceL1) // → alive，间隔 60s

	if !tr.ClaimL1(1) {
		t.Fatal("首次应到期")
	}
	// 探活还在跑（没有 Report），下一个 tick 不能再抢到
	for i := 0; i < 10; i++ {
		if tr.ClaimL1(1) {
			t.Fatal("预占后不该被再次抢到 —— 会导致同一个 Route 被并发探两次")
		}
	}

	*now = now.Add(61 * time.Second)
	if !tr.ClaimL1(1) {
		t.Error("间隔已过，应重新到期")
	}
}

// dead 用固定短周期（20s/30s），不做指数退避 —— 那会把恢复发现延迟拉到分钟级。
func TestClaim_DeadUsesShortFixedIntervals(t *testing.T) {
	tr, fs, now := newTestTracker(t)
	fs.s.FailThreshold = 1
	fs.s.L1IntervalDeadSec = 20
	fs.s.L2IntervalDeadSec = 30

	report(tr, 1, VerdictUnavailable, SourceL2)
	tr.ClaimL1(1)
	tr.ClaimL2(1)

	*now = now.Add(21 * time.Second)
	if !tr.ClaimL1(1) {
		t.Error("dead 的 L1 应 20 秒一轮")
	}
	if tr.ClaimL2(1) {
		t.Error("dead 的 L2 是 30 秒，21 秒时还不该到期")
	}

	*now = now.Add(10 * time.Second)
	if !tr.ClaimL2(1) {
		t.Error("31 秒后 dead 的 L2 应到期")
	}
}

// 久治不愈的站只放宽 L2（省 token），L1 保持 20 秒不变。
// L1 是零成本的，而且它转通会立即触发 L2（§4.4b），所以放宽 L2 不影响发现速度。
func TestClaim_LongDeadWidensL2ButNotL1(t *testing.T) {
	tr, fs, now := newTestTracker(t)
	fs.s.FailThreshold = 1
	fs.s.L1IntervalDeadSec = 20
	fs.s.L2IntervalDeadSec = 30

	for i := 0; i <= longDeadFails; i++ {
		report(tr, 1, VerdictUnavailable, SourceL2)
	}

	tr.ClaimL1(1)
	tr.ClaimL2(1)

	*now = now.Add(21 * time.Second)
	if !tr.ClaimL1(1) {
		t.Error("久死站的 L1 仍应保持 20 秒 —— 它零成本，且转通会立即触发 L2")
	}

	*now = now.Add(30 * time.Second) // 累计 51s，超过原本的 30s L2 间隔
	if tr.ClaimL2(1) {
		t.Error("久死站的 L2 应已放宽到 2 分钟")
	}
	*now = now.Add(90 * time.Second) // 累计 141s > 120s
	if !tr.ClaimL2(1) {
		t.Error("超过 2 分钟后应到期")
	}
}

// piggyback：真实请求成功等价于一次 L2 探活，省下探活 token。
func TestClaim_PiggybackSkipsL2AfterRealSuccess(t *testing.T) {
	tr, fs, now := newTestTracker(t)
	fs.s.OKThreshold = 1
	fs.s.PiggybackEnabled = true
	fs.s.L2IntervalAliveSec = 300

	report(tr, 1, VerdictOK, SourceReal) // → alive，且刷新 lastRealOKAt
	tr.ClaimL2(1)

	*now = now.Add(301 * time.Second)
	report(tr, 1, VerdictOK, SourceReal) // 又一次真实成功

	*now = now.Add(10 * time.Second)
	if tr.ClaimL2(1) {
		t.Error("距上次真实成功仅 10 秒，应被 piggyback 跳过")
	}

	*now = now.Add(300 * time.Second)
	if !tr.ClaimL2(1) {
		t.Error("超过 L2 间隔且无新的真实成功，应正常探活")
	}
}

// piggyback 对 dead 站必须失效。死站的「上次真实成功」可能是半小时前，
// 拿它跳过探活就等于永远不再探 —— 恰好废掉快速恢复。
func TestClaim_PiggybackDoesNotApplyToDeadRoutes(t *testing.T) {
	tr, fs, now := newTestTracker(t)
	fs.s.OKThreshold = 1
	fs.s.FailThreshold = 1
	fs.s.PiggybackEnabled = true
	fs.s.L2IntervalDeadSec = 30

	report(tr, 1, VerdictOK, SourceReal) // 记下 lastRealOKAt
	report(tr, 1, VerdictUnavailable, SourceL2)
	if tr.State(1) != model.StateDead {
		t.Fatal("前置条件：应为 dead")
	}

	tr.ClaimL2(1)
	*now = now.Add(31 * time.Second)
	if !tr.ClaimL2(1) {
		t.Error("dead 站不该被 piggyback 跳过 —— 那会让它永远不再被探活")
	}
}

// 关掉 piggyback 就该老老实实按周期探。
func TestClaim_PiggybackCanBeDisabled(t *testing.T) {
	tr, fs, now := newTestTracker(t)
	fs.s.OKThreshold = 1
	fs.s.PiggybackEnabled = false
	fs.s.L2IntervalAliveSec = 300

	report(tr, 1, VerdictOK, SourceReal)
	tr.ClaimL2(1)

	*now = now.Add(301 * time.Second)
	if !tr.ClaimL2(1) {
		t.Error("piggyback 关闭时应按周期正常探活")
	}
}

// TriggerL2 清掉预占，让下一个 tick 立刻探（§4.4b / §4.5 的事件驱动）。
func TestTrigger_ClearsClaimForImmediateProbe(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.OKThreshold = 1

	report(tr, 1, VerdictOK, SourceL2)
	tr.ClaimL1(1)
	tr.ClaimL2(1)
	if tr.ClaimL2(1) {
		t.Fatal("前置条件：应已被预占")
	}

	tr.TriggerL2(1)
	if !tr.ClaimL2(1) {
		t.Error("TriggerL2 后应立即可探")
	}
	tr.TriggerL1(1)
	if !tr.ClaimL1(1) {
		t.Error("TriggerL1 后应立即可探")
	}
}

// ── §4.8 暂停/恢复 ───────────────────────────────────────

// 恢复时全部置 unknown：暂停期间的状态已经过期，且 unknown 是乐观的，
// 恢复瞬间就能承接流量，不会「刚点开就 503」。
func TestResetAll_ClearsStateAndClaims(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.FailThreshold = 1

	report(tr, 1, VerdictUnavailable, SourceL2)
	tr.Report(Report{RouteID: 2, Verdict: VerdictRateLimited, Source: SourceL2})
	tr.ClaimL1(1)
	tr.ClaimL2(1)

	tr.ResetAll()

	if got := tr.State(1); got != model.StateUnknown {
		t.Errorf("恢复后应置 unknown，得到 %s", got)
	}
	if tr.CoolingDown(2) {
		t.Error("恢复后应清除冷却")
	}
	if !tr.ClaimL1(1) || !tr.ClaimL2(1) {
		t.Error("恢复后应立即可探活（§4.8：全量 L1，再对需要的跑 L2）")
	}
	if n := tr.Status(1).ConsecutiveFail; n != 0 {
		t.Errorf("恢复后失败计数应清零，得到 %d", n)
	}
}

// ResetAll 不能碰在途计数：暂停不杀已建立的流式连接（§4.8），
// 那些请求还在跑，清零它们的额度会让并发上限失效。
func TestResetAll_PreservesInFlight(t *testing.T) {
	tr, _, _ := newTestTracker(t)
	release := acquire(t, tr, 1)
	defer release()

	tr.ResetAll()

	if got := tr.InFlight(1); got != 1 {
		t.Errorf("ResetAll 不该影响在途计数（暂停不杀进行中的流），得到 %d", got)
	}
}

// ── 清理 ────────────────────────────────────────────────

// 删掉的 Route 若 ID 被复用，残留的失败计数会被新 Route 继承。
func TestRetainOnly_DropsRemovedRoutes(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.FailThreshold = 1

	report(tr, 1, VerdictUnavailable, SourceL2)
	report(tr, 2, VerdictUnavailable, SourceL2)

	tr.RetainOnly(map[int64]bool{1: true})

	if got := tr.State(1); got != model.StateDead {
		t.Errorf("保留的 Route 状态应不变，得到 %s", got)
	}
	if got := tr.State(2); got != model.StateUnknown {
		t.Errorf("被删的 Route 应恢复为 unknown（即已被遗忘），得到 %s", got)
	}
	if n := len(tr.AllStatus()); n != 1 {
		t.Errorf("应只剩 1 个 Route，得到 %d", n)
	}
}

func TestForget_DropsSingleRoute(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.FailThreshold = 1

	report(tr, 1, VerdictUnavailable, SourceL2)
	tr.Forget(1)

	if got := tr.State(1); got != model.StateUnknown {
		t.Errorf("Forget 后应回到 unknown，得到 %s", got)
	}
}

// ── 降级路径 ────────────────────────────────────────────

// 读不到设置时用默认值继续跑，而不是跳过判定。
// 跳过的话，配置源出问题的那段时间里没有任何站会被判死 ——
// 而那正是最可能出问题的时候。
func TestReport_FallsBackToDefaultsWhenSettingsUnavailable(t *testing.T) {
	fs := &fakeSettings{s: model.Settings{}, err: errors.New("库读不出来")}
	tr := NewTracker(fs)

	// 默认 FailThreshold = 2
	report(tr, 1, VerdictUnavailable, SourceL2)
	if tr.State(1) == model.StateDead {
		t.Error("默认阈值是 2，第 1 次不该判死")
	}
	report(tr, 1, VerdictUnavailable, SourceL2)
	if tr.State(1) != model.StateDead {
		t.Error("读不到设置时应按默认阈值继续判定，而不是永不判死")
	}
}

// nil settings 也不能崩 —— 测试与部分装配路径会这么传。
func TestReport_NilSettingsSourceUsesDefaults(t *testing.T) {
	tr := NewTracker(nil)
	report(tr, 1, VerdictUnavailable, SourceL2)
	report(tr, 1, VerdictUnavailable, SourceL2)
	if tr.State(1) != model.StateDead {
		t.Error("nil settings 应回落到默认值")
	}
}

// Status 里的冷却截止时刻过期后不该再报告 —— 「冷却到 10 分钟前」
// 在界面上读起来像个 bug。
func TestStatus_ExpiredCooldownIsNotReported(t *testing.T) {
	tr, fs, now := newTestTracker(t)
	fs.s.CooldownSec = 60

	tr.Report(Report{RouteID: 1, Verdict: VerdictRateLimited, Source: SourceL2})
	if tr.Status(1).CooldownUntil == 0 {
		t.Error("冷却中应报告截止时刻")
	}

	*now = now.Add(61 * time.Second)
	if got := tr.Status(1).CooldownUntil; got != 0 {
		t.Errorf("冷却已过期，不该再报告截止时刻，得到 %d", got)
	}
}

// TTFT 只在测到时更新。探活失败时 TTFT 为 0，不能把上次的有效值冲掉 ——
// 那样界面上的延迟会在每次失败后变成 0，看不出这个站原本有多快。
func TestReport_TTFTOnlyUpdatesWhenMeasured(t *testing.T) {
	tr, _, _ := newTestTracker(t)

	tr.Report(Report{RouteID: 1, Verdict: VerdictOK, Source: SourceL2, TTFT: 3500 * time.Millisecond})
	if got := tr.Status(1).LastTTFTMS; got != 3500 {
		t.Fatalf("应记录 TTFT，得到 %d", got)
	}

	tr.Report(Report{RouteID: 1, Verdict: VerdictOK, Source: SourceL2}) // 未测到
	if got := tr.Status(1).LastTTFTMS; got != 3500 {
		t.Errorf("未测到 TTFT 时应保留上次的值，得到 %d", got)
	}
}
