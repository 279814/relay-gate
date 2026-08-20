package outbound

import (
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// ── 各阶段从 SentAt 起算，而不是四段累加（计划第 6 条）────────

// 这是本文件最要紧的一条。四段累加会让实际可用时间变成配置值的四倍：
// response_header(1200) + first_byte(1200) + first_semantic(1200) 累加起来是
// 一小时，而 real_total_sec 只有 1800 秒 —— 于是三个阶段上限里有两个永远
// 不会触发，配置写了却是死的。
func TestBudget_EveryDeadlineIsMeasuredFromSentAt(t *testing.T) {
	sent := time.Unix(1_700_000_000, 0)
	budget := Budget{
		Connect:       30 * time.Second,
		ResponseHead:  100 * time.Second,
		FirstByte:     200 * time.Second,
		FirstEvent:    250 * time.Second,
		FirstSemantic: 300 * time.Second,
		Idle:          60 * time.Second,
		Total:         600 * time.Second,
	}

	deadlines := []struct {
		name string
		got  time.Time
		want time.Time
	}{
		{"response_header", budget.ResponseHeadDeadline(sent), sent.Add(100 * time.Second)},
		{"first_byte", budget.FirstByteDeadline(sent), sent.Add(200 * time.Second)},
		{"first_event", budget.FirstEventDeadline(sent), sent.Add(250 * time.Second)},
		{"first_semantic", budget.FirstSemanticDeadline(sent), sent.Add(300 * time.Second)},
		{"total", budget.TotalDeadline(sent), sent.Add(600 * time.Second)},
	}
	for _, deadline := range deadlines {
		if !deadline.got.Equal(deadline.want) {
			t.Errorf("%s 应从 SentAt 起算：want %v got %v（差 %v，说明是累加的）",
				deadline.name, deadline.want, deadline.got, deadline.got.Sub(deadline.want))
		}
	}
}

// total 是最外层硬上限：任何阶段的 deadline 都不得越过它。
//
// 配置层已经校验了「total 覆盖各阶段」，但那是保存时的约束；运行时读到的
// 可能是升级前存下的旧值，此时越界的阶段上限会让 total 形同虚设。
func TestBudget_StageDeadlinesNeverExceedTotal(t *testing.T) {
	sent := time.Unix(1_700_000_000, 0)
	budget := Budget{
		ResponseHead:  900 * time.Second,
		FirstByte:     900 * time.Second,
		FirstEvent:    900 * time.Second,
		FirstSemantic: 900 * time.Second,
		Idle:          60 * time.Second,
		Total:         120 * time.Second, // 比每个阶段都短
	}
	total := budget.TotalDeadline(sent)

	stages := map[string]time.Time{
		"response_header": budget.ResponseHeadDeadline(sent),
		"first_byte":      budget.FirstByteDeadline(sent),
		"first_event":     budget.FirstEventDeadline(sent),
		"first_semantic":  budget.FirstSemanticDeadline(sent),
	}
	for name, deadline := range stages {
		if deadline.After(total) {
			t.Errorf("%s 的 deadline 越过了 total（%v > %v）——total 是最外层硬上限",
				name, deadline, total)
		}
	}
}

// 零值阶段表示「这个场景不观察这一段」，此时该阶段回落到 total。
//
// 不能回落到 0：那样 context.WithDeadline 会立刻到期，一个只配了
// l1_total_sec 的场景会变成「每次探活都瞬间超时」。
func TestBudget_ZeroStageFallsBackToTotal(t *testing.T) {
	sent := time.Unix(1_700_000_000, 0)
	// L1 只有 connect 与 total 两项（§7.4 的表里 L1 就是这两行）。
	budget := Budget{Connect: 30 * time.Second, Total: 90 * time.Second}

	want := sent.Add(90 * time.Second)
	for name, got := range map[string]time.Time{
		"response_header": budget.ResponseHeadDeadline(sent),
		"first_byte":      budget.FirstByteDeadline(sent),
		"first_event":     budget.FirstEventDeadline(sent),
		"first_semantic":  budget.FirstSemanticDeadline(sent),
	} {
		if !got.Equal(want) {
			t.Errorf("%s 未配置时应回落到 total（%v），得到 %v", name, want, got)
		}
	}
}

// ── 首语义之后才启用可重置的 idle（计划第 7 条）──────────────

func TestBudget_IdleTimerOnlyAfterFirstSemantic(t *testing.T) {
	budget := Budget{Idle: 60 * time.Second, Total: 600 * time.Second}

	if got := budget.IdleTimeout(); got != 60*time.Second {
		t.Errorf("idle 上限 want 60s got %v", got)
	}
	// 没配 idle 时不能给 0（timer 会立刻开火），回落到 total。
	noIdle := Budget{Total: 600 * time.Second}
	if got := noIdle.IdleTimeout(); got != 600*time.Second {
		t.Errorf("未配 idle 时应回落到 total，得到 %v", got)
	}
}

// ── 四个场景各自的预算（§7.4 的表）──────────────────────────

func TestBudgetsFromSettings(t *testing.T) {
	settings := model.DefaultSettings()

	cases := []struct {
		name          string
		got           Budget
		wantConnect   time.Duration
		wantTotal     time.Duration
		wantSemantic  time.Duration
		wantHasStages bool
	}{
		{"real", RealBudget(settings), 30 * time.Second, 1800 * time.Second, 1200 * time.Second, true},
		// L1 只有 connect + total：它是传输层探测，没有「首语义」这回事。
		{"l1", L1Budget(settings), 30 * time.Second, 90 * time.Second, 0, false},
		{"l2", L2Budget(settings), 30 * time.Second, 600 * time.Second, 300 * time.Second, true},
		// count_tokens 是非流式的单次调用，同样只有 connect + total（§7.4）。
		{"count_tokens", CountTokensBudget(settings), 30 * time.Second, 180 * time.Second, 0, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.got.Connect != testCase.wantConnect {
				t.Errorf("connect want %v got %v", testCase.wantConnect, testCase.got.Connect)
			}
			if testCase.got.Total != testCase.wantTotal {
				t.Errorf("total want %v got %v", testCase.wantTotal, testCase.got.Total)
			}
			if testCase.got.FirstSemantic != testCase.wantSemantic {
				t.Errorf("first_semantic want %v got %v",
					testCase.wantSemantic, testCase.got.FirstSemantic)
			}
			// 每个场景的所有非零值都必须非零：一个 0 会让
			// context.WithTimeout(0) 立刻超时，表现为「这个场景全部失败」。
			if testCase.got.Connect == 0 || testCase.got.Total == 0 {
				t.Error("connect 与 total 必须非零")
			}
		})
	}
}

// 每个场景各拿自己的 connect 预算 —— 这正是 P0-04 的目标：
// 「让 L1/L2 配置真正生效」。共用一个值的话，改 l2_connect_sec 不会有任何效果。
func TestBudgets_ConnectTimeoutsAreIndependent(t *testing.T) {
	settings := model.DefaultSettings()
	settings.RealConnectSec = 11
	settings.L1ConnectSec = 22
	settings.L2ConnectSec = 33
	settings.CountTokensConnectSec = 44

	got := map[string]time.Duration{
		"real":         RealBudget(settings).Connect,
		"l1":           L1Budget(settings).Connect,
		"l2":           L2Budget(settings).Connect,
		"count_tokens": CountTokensBudget(settings).Connect,
	}
	want := map[string]time.Duration{
		"real": 11 * time.Second, "l1": 22 * time.Second,
		"l2": 33 * time.Second, "count_tokens": 44 * time.Second,
	}
	for name, wantValue := range want {
		if got[name] != wantValue {
			t.Errorf("%s 的 connect 预算 want %v got %v —— 各场景必须独立取值",
				name, wantValue, got[name])
		}
	}
}

// 探活超时绝不缩短真实请求的超时（§7.4 末句）。
func TestBudgets_ProbeTimeoutsDoNotAffectReal(t *testing.T) {
	settings := model.DefaultSettings()
	real := RealBudget(settings)

	settings.L1ConnectSec = 1
	settings.L1TotalSec = 1
	settings.L2ConnectSec = 1
	settings.L2TotalSec = 2
	settings.L2FirstSemanticSec = 1

	if again := RealBudget(settings); again != real {
		t.Errorf("把探活超时全调到最小后，真实请求的预算不该变化：\nwant %+v\ngot  %+v",
			real, again)
	}
}

// ── 剩余预算夹取（重试路径要用）────────────────────────────

// 一次客户端请求的多次尝试共享同一份总预算。不夹的话，3 次尝试各拿一份
// 完整的 30 分钟，客户端最坏等 90 分钟。
func TestBudget_CapTotalClampsToRemaining(t *testing.T) {
	budget := Budget{Connect: 30 * time.Second, Total: 600 * time.Second,
		FirstSemantic: 300 * time.Second, Idle: 60 * time.Second}

	capped := budget.CapTotal(120 * time.Second)
	if capped.Total != 120*time.Second {
		t.Errorf("剩余预算更短时应夹到剩余值，得到 %v", capped.Total)
	}
	// 夹了 total 之后，越界的阶段上限也必须跟着收 —— 否则
	// first_semantic(300s) 会比 total(120s) 还长，那个阶段就永不触发。
	if deadline := capped.FirstSemanticDeadline(time.Unix(0, 0)); deadline.After(capped.TotalDeadline(time.Unix(0, 0))) {
		t.Error("夹取 total 后，阶段 deadline 仍越界")
	}
	// 剩余预算更长时不动：那是「配置就是这么长」，不该被放大。
	if got := budget.CapTotal(9999 * time.Second); got.Total != 600*time.Second {
		t.Errorf("剩余预算更长时不该放大 total，得到 %v", got.Total)
	}
}
