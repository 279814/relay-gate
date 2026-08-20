package outbound

import (
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// Budget 是一次出站请求的全部时间预算（§7.4）。
//
// 四个观察点（response_header / first_byte / first_event / first_semantic）
// **都从 SentAt 起算，不是顺序累加**。这一条是本类型存在的主要理由：
// 累加会让实际可用时间变成配置值之和 —— 默认配置下三段累加是一小时，
// 而 real_total_sec 只有 1800 秒，于是其中两段永远不会触发。配置写了却是死的。
//
// Total 是最外层硬上限，任何阶段都不得越过它。
type Budget struct {
	// Connect 覆盖 DNS、TCP、代理 CONNECT 与 TLS 握手全程，进连接池身份。
	Connect time.Duration
	// ResponseHead ~ FirstSemantic 是四个观察点的上限。零值表示这个场景
	// 不单独观察该阶段（L1 与 count_tokens 就只有 connect + total）。
	ResponseHead  time.Duration
	FirstByte     time.Duration
	FirstEvent    time.Duration
	FirstSemantic time.Duration
	// Idle 是**首语义之后**流内两个 chunk 之间的静默上限，可重置。
	//
	// 只在首语义之后启用是刻意的：长思考期间流上本就没有数据，
	// 提前启用 idle 会把正常的思考判成「流中断了」。
	Idle time.Duration
	// Total 是这次请求的硬上限。
	Total time.Duration
}

// RealBudget 是真实请求的预算。
func RealBudget(settings model.Settings) Budget {
	return Budget{
		Connect:       seconds(settings.RealConnectSec),
		ResponseHead:  stageOrLegacy(settings.RealResponseHeaderSec, settings.RealFirstTokenSec),
		FirstByte:     stageOrLegacy(settings.RealFirstByteSec, settings.RealFirstTokenSec),
		FirstEvent:    stageOrLegacy(settings.RealFirstByteSec, settings.RealFirstTokenSec),
		FirstSemantic: stageOrLegacy(settings.RealFirstSemanticSec, settings.RealFirstTokenSec),
		Idle:          seconds(settings.RealIdleSec),
		Total:         seconds(settings.RealTotalSec),
	}
}

// L1Budget 是传输层探测的预算。
//
// 只有 connect 与 total（§7.4 的表里 L1 就是这两行）：L1 拿到任何响应就算通，
// 没有「首事件」「首语义」这回事，给它们配上限只会多两个永不触发的旋钮。
func L1Budget(settings model.Settings) Budget {
	return Budget{
		Connect: seconds(settings.L1ConnectSec),
		Total:   seconds(settings.L1TotalSec),
	}
}

// L2Budget 是模型层探测的预算。
//
// 与真实请求**完全独立**，这正是「容忍长思考」与「快速判死」能同时成立的
// 原因：L2 只等 300 秒就判死，而真实请求可以等 1200 秒。共用一份的话，
// 想让死站更快被发现就必然砍掉正常的长思考。
func L2Budget(settings model.Settings) Budget {
	return Budget{
		Connect:       seconds(settings.L2ConnectSec),
		ResponseHead:  stageOrLegacy(settings.L2ResponseHeaderSec, settings.L2FirstTokenSec),
		FirstByte:     stageOrLegacy(settings.L2FirstByteSec, settings.L2FirstTokenSec),
		FirstEvent:    stageOrLegacy(settings.L2FirstEventSec, settings.L2FirstTokenSec),
		FirstSemantic: stageOrLegacy(settings.L2FirstSemanticSec, settings.L2FirstTokenSec),
		Idle:          seconds(settings.L2IdleSec),
		Total:         seconds(settings.L2TotalSec),
	}
}

// CountTokensBudget 是 count_tokens 的预算。
//
// 非流式的单次调用，同样只有 connect + total：它要么一次性回一个
// {"input_tokens":N}，要么就该降级本地粗算，中间没有需要分段观察的阶段。
func CountTokensBudget(settings model.Settings) Budget {
	return Budget{
		Connect: seconds(settings.CountTokensConnectSec),
		Total:   seconds(settings.CountTokensTotalSec),
	}
}

// ResponseHeadDeadline 等一系列方法返回各阶段的绝对时刻。
//
// 返回绝对时刻而不是 duration：调用方手上是 SentAt，而「从 SentAt 起算」
// 这条规则必须由本类型保证 —— 交给调用方自己加，就会有人在某处写成
// time.Now().Add(...)，那又变回累加了。
func (budget Budget) ResponseHeadDeadline(sentAt time.Time) time.Time {
	return budget.stageDeadline(sentAt, budget.ResponseHead)
}

func (budget Budget) FirstByteDeadline(sentAt time.Time) time.Time {
	return budget.stageDeadline(sentAt, budget.FirstByte)
}

func (budget Budget) FirstEventDeadline(sentAt time.Time) time.Time {
	return budget.stageDeadline(sentAt, budget.FirstEvent)
}

func (budget Budget) FirstSemanticDeadline(sentAt time.Time) time.Time {
	return budget.stageDeadline(sentAt, budget.FirstSemantic)
}

func (budget Budget) TotalDeadline(sentAt time.Time) time.Time {
	return sentAt.Add(budget.Total)
}

// stageDeadline 把一个阶段上限换算成绝对时刻，并夹在 total 之内。
//
// 零值回落到 total 而不是零：零会让 context.WithDeadline 立刻到期，
// 表现为「这个场景的请求全部瞬间失败」，而那与「不观察这一段」相差极远。
func (budget Budget) stageDeadline(sentAt time.Time, stage time.Duration) time.Time {
	total := budget.TotalDeadline(sentAt)
	if stage <= 0 {
		return total
	}
	if deadline := sentAt.Add(stage); deadline.Before(total) {
		return deadline
	}
	return total
}

// IdleTimeout 是首语义之后的流内静默上限。
func (budget Budget) IdleTimeout() time.Duration {
	if budget.Idle <= 0 {
		return budget.Total
	}
	return budget.Idle
}

// CapTotal 把总预算夹到 remaining。
//
// 供重试路径用：一次客户端请求的多次尝试共享同一份总预算，不夹的话
// 3 次尝试各拿一份完整的 30 分钟，客户端最坏等 90 分钟。
//
// 只夹 Total，各阶段上限不动 —— stageDeadline 会自己夹在新的 total 之内。
// 那样比逐个改阶段值更不容易漏：将来加一个阶段，它自动受约束。
func (budget Budget) CapTotal(remaining time.Duration) Budget {
	if remaining > 0 && remaining < budget.Total {
		budget.Total = remaining
	}
	return budget
}

func seconds(value int) time.Duration {
	if value <= 0 {
		return 0
	}
	return time.Duration(value) * time.Second
}

// stageOrLegacy 取分阶段的值，为空时回落到那个粗粒度的旧字段。
//
// 存在的理由是一个真实的失效风险：`real_first_token_sec` 与
// `l2_first_token_sec` 是 schema 1 的粗旋钮，schema 2 把它们拆成了四个阶段。
// store.SaveSettings 会在写入时把旧值展开到新字段（见那里的 adapter），
// 所以**从库里读出来的**配置两套都填好了。
//
// 但手工构造 model.Settings 的调用方（测试、冒烟脚本、将来的某个内部工具）
// 只设旧字段是很自然的写法，而那时四个新字段还是 DefaultSettings 的 1200 秒 ——
// 于是「首 Token 超时设成 2 秒」静默变成 1200 秒，被 total 兜住。症状是
// 「超时配了不生效」，而它不报错。
//
// 这层回落在 P0-14 把管理 API 迁到分阶段 DTO、旧字段删掉之后即可移除。
func stageOrLegacy(stage, legacy int) time.Duration {
	if stage > 0 {
		return seconds(stage)
	}
	return seconds(legacy)
}
