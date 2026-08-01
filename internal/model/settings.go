package model

// MinRealFirstTokenSec 是真实请求首 Token 超时的**硬下限**：5 分钟。
//
// 低于该值的配置一律拒绝保存，而不是静默取整——静默修正会让人误以为改生效了。
//
// 为什么有下限：这个参数调小的代价远大于调大的代价，不对称。
//   - 调大：一个真死的站多占住一个连接，但探活在旁路独立判死（L2 只等 120s），
//     死站会被标 dead 并从选路剔除，不影响后续请求。
//   - 调小：正常的长思考被拦腰砍断，客户端拿到「上游超时」，而这个站其实是好的，
//     还会因此被计入失败 → 标 dead → 好站被踢出池子。
//
// M0 实测长思考首 Token 22.4–32.0s，5 分钟约为实测最坏值的 9 倍。
// 但实测是乐观下界（空上下文、无扩展思考），真实场景可能到分钟级，故留此余量。
const MinRealFirstTokenSec = 300

// MaxRetryAttempts 是 RetryMaxAttempts 的上限。
//
// 存在的理由不是「5 次刚好够」，而是防一个手滑：这个数字直接决定
// **一次**客户端请求最多向公益站发几次完整请求（body 可达几 MB，
// 且每次都可能真的消耗 token）。填成 100 不会报错、不会崩，只会让
// 每个失败请求悄悄放大成 100 次上游调用 —— 而额度是花在别人的站上。
//
// 重试次数还有一条天然上限（试过的 Route 会被排除，最多试完所有 Route），
// 但那取决于配置，挡不住「一个 Route 被反复……」之类的将来改动。
const MaxRetryAttempts = 5

// Settings 是全局运行配置，存在 setting 表里（单行 JSON），UI 可热改。
//
// 时间单位统一用秒并在字段名里标出（*Sec），避免「这个数是毫秒还是秒」的歧义——
// 混用单位是这类配置最常见的 bug 来源。
type Settings struct {
	// ── 真实请求超时（§4.2）────────────────────────────────
	RealConnectSec    int `json:"real_connect_sec"`
	RealFirstTokenSec int `json:"real_first_token_sec"` // 有 300s 硬下限
	RealIdleSec       int `json:"real_idle_sec"`        // 流内两个 chunk 之间的静默上限
	RealTotalSec      int `json:"real_total_sec"`

	// ── 探活超时 ──────────────────────────────────────────
	// L2 独立于真实请求：这正是「容忍长思考」与「快速判死」能同时成立的原因。
	L2ConnectSec    int `json:"l2_connect_sec"`
	L2FirstTokenSec int `json:"l2_first_token_sec"`
	L2TotalSec      int `json:"l2_total_sec"`
	L1ConnectSec    int `json:"l1_connect_sec"`
	L1TotalSec      int `json:"l1_total_sec"`

	CountTokensSec int `json:"count_tokens_sec"`

	// ── 探活调度（§4.6）───────────────────────────────────
	L1IntervalAliveSec int `json:"l1_interval_alive_sec"`
	L1IntervalDeadSec  int `json:"l1_interval_dead_sec"`
	L2IntervalAliveSec int `json:"l2_interval_alive_sec"`
	L2IntervalDeadSec  int `json:"l2_interval_dead_sec"`

	// ── 健康状态机（§4.3 / §4.4）──────────────────────────
	FailThreshold int `json:"fail_threshold"` // 连续失败几次判 dead
	OKThreshold   int `json:"ok_threshold"`   // 连续成功几次升 alive
	CooldownSec   int `json:"cooldown_sec"`   // 429 冷却时长（无 retry-after 时）

	GlobalL2Concurrency int  `json:"global_l2_concurrency"`
	ProbeEnabled        bool `json:"probe_enabled"`
	PiggybackEnabled    bool `json:"piggyback_enabled"`
	HalfOpenEnabled     bool `json:"half_open_enabled"`

	// ── 请求内重试（§3.5）────────────────────────────────
	//
	// RetryMaxAttempts 是**总尝试次数**（含第一次），不是「额外重试几次」。
	// 1 = 不重试。默认 3，对应 §3.5 的「最多 2 次重试」。
	//
	// 只用一个旋钮而不是「开关 + 次数」：两个字段表达同一件事时，
	// enabled=true 且 attempts=1 这种自相矛盾的组合就必须有人去解释，
	// 而它没有任何有用的语义。
	RetryMaxAttempts int `json:"retry_max_attempts"`

	// ── 样本记录（§3.6.3）────────────────────────────────
	//
	// 三个体积上限都以 **0 = 不限**（完整留档）为默认值。留档的价值恰恰在
	// 「到底是哪些字节」—— 截断过的样本没法拿去逐字段比对，而那是 §3.6.1
	// 给这个功能定的头号用途。
	//
	// 代价是磁盘与内存，且**由上游的响应大小决定**，不再由我们封顶：
	//   - 磁盘：最坏约 keep_count × (in + out + resp)。300 条 × 单条几 MB
	//     可以到 GB 级；靠 keep_count(300) 与 keep_days(7) 兜住。
	//   - 内存：每个**在途**请求会在 RAM 里攒一份完整响应副本（采集用 tee）。
	//     并发 N 路就是 N 份。
	// 磁盘或内存吃紧时，把这三项调回非零即恢复原来的封顶行为。
	SampleEnabled bool `json:"sample_enabled"`
	// SampleMaxBodyBytes 是 in_body / out_body 的留档上限。0 = 不截断。
	SampleMaxBodyBytes int `json:"sample_max_body_bytes"`
	// SampleRespHeadBytes / SampleRespTailBytes 是响应体的留头/留尾上限。
	// **两者同时为 0** 表示完整保留（不分头尾、不插省略标记）；
	// 只有一个为 0 仍是有界的（例如头 0 尾 8KB = 只留最后 8KB）。
	SampleRespHeadBytes int `json:"sample_resp_head_bytes"`
	SampleRespTailBytes int `json:"sample_resp_tail_bytes"`
	SampleKeepCount     int `json:"sample_keep_count"`
	SampleKeepDays      int `json:"sample_keep_days"`
	SampleQueueSize     int `json:"sample_queue_size"`

	// ── 请求日志（M6）──────────────────────────────────────
	//
	// 与样本是**两套独立的旋钮**，不共用。样本一条可达几 MB（现在不封顶），
	// 日志一行几百字节 —— 共用一个 keep_count 会让「多留点日志」的代价
	// 变成磁盘翻 GB，于是没人敢调大它。
	//
	// 日志也不跟着 sample_enabled 关：它是判断「重试策略有没有用」的唯一
	// 依据，而那个判断恰恰在样本被关掉、只留统计的场景下最需要。
	RequestLogEnabled bool `json:"request_log_enabled"`
	// RequestLogKeepCount 按**客户端请求**计（一组尝试算一条），不是按行。
	// 按行的话，「保留 1000 条」在重试频繁时只能覆盖 300 多次请求，
	// 而覆盖多久完全取决于故障率 —— 一个说不清含义的数字。
	RequestLogKeepCount int `json:"request_log_keep_count"`
	RequestLogKeepDays  int `json:"request_log_keep_days"`
	RequestLogQueueSize int `json:"request_log_queue_size"`
}

// DefaultSettings 返回 §4.2 超时矩阵与 §3.6.3 样本上限的默认值。
func DefaultSettings() Settings {
	return Settings{
		RealConnectSec:    30,
		RealFirstTokenSec: 1200, // 20 分钟
		RealIdleSec:       600,  // 10 分钟
		RealTotalSec:      1800, // 30 分钟

		L2ConnectSec:    30,
		L2FirstTokenSec: 120, // 实测 1+1=? 只需 3-6s，120s 已是 20 倍余量
		L2TotalSec:      150,
		L1ConnectSec:    15,
		L1TotalSec:      25,

		CountTokensSec: 60,

		L1IntervalAliveSec: 60,
		L1IntervalDeadSec:  20, // 固定短周期，不做指数退避（§4.4）
		L2IntervalAliveSec: 300,
		L2IntervalDeadSec:  30,

		FailThreshold: 2,
		OKThreshold:   2,
		CooldownSec:   60,

		GlobalL2Concurrency: 3,
		ProbeEnabled:        true,
		PiggybackEnabled:    true,
		HalfOpenEnabled:     true,

		RetryMaxAttempts: 3, // 初次 + 最多 2 次重试（§3.5）

		SampleEnabled:       true,
		SampleMaxBodyBytes:  0, // 0 = 不截断，完整保留入站与出站请求体
		SampleRespHeadBytes: 0, // 0 = 完整保留响应（不再分头尾）
		SampleRespTailBytes: 0,
		SampleKeepCount:     300, // 从 500 降至 300
		SampleKeepDays:      7,
		SampleQueueSize:     256,

		// 日志比样本留得多得多：一行几百字节，5000 条客户端请求
		// 也就几 MB，而「最近一周的重试到底有没有用」需要足够的样本量
		// 才算得出有意义的比例。
		RequestLogEnabled:   true,
		RequestLogKeepCount: 5000,
		RequestLogKeepDays:  7,
		RequestLogQueueSize: 512,
	}
}

func (s *Settings) Validate() error {
	// 唯一有硬下限的项，单独且显式地校验，错误信息说清为什么。
	if s.RealFirstTokenSec < MinRealFirstTokenSec {
		return invalid("real_first_token_sec 不得低于 %d 秒（5 分钟）。"+
			"收到 %d。调小的代价是正常长思考被砍断并把好站判死；"+
			"若目的是让死站更快被发现，请调 l2_first_token_sec，探活与真实请求的超时是分开的",
			MinRealFirstTokenSec, s.RealFirstTokenSec)
	}

	positives := []struct {
		name string
		val  int
	}{
		{"real_connect_sec", s.RealConnectSec},
		{"real_idle_sec", s.RealIdleSec},
		{"real_total_sec", s.RealTotalSec},
		{"l2_connect_sec", s.L2ConnectSec},
		{"l2_first_token_sec", s.L2FirstTokenSec},
		{"l2_total_sec", s.L2TotalSec},
		{"l1_connect_sec", s.L1ConnectSec},
		{"l1_total_sec", s.L1TotalSec},
		{"count_tokens_sec", s.CountTokensSec},
		{"l1_interval_alive_sec", s.L1IntervalAliveSec},
		{"l1_interval_dead_sec", s.L1IntervalDeadSec},
		{"l2_interval_alive_sec", s.L2IntervalAliveSec},
		{"l2_interval_dead_sec", s.L2IntervalDeadSec},
		{"fail_threshold", s.FailThreshold},
		{"ok_threshold", s.OKThreshold},
		{"cooldown_sec", s.CooldownSec},
		{"global_l2_concurrency", s.GlobalL2Concurrency},
		// sample_max_body_bytes **不在**这里：它的 0 是「不截断」，是当前的
		// 默认值。归进正数校验会让默认配置自己校验不过 —— 保存一次设置就
		// 400，而且错误信息还说「必须为正数」，完全指错方向。
		// 它的下限（不为负）在下面与另两个体积上限一起判。
		{"sample_keep_count", s.SampleKeepCount},
		{"sample_keep_days", s.SampleKeepDays},
		{"sample_queue_size", s.SampleQueueSize},
		// 1 = 不重试。0 会让重试循环一次都不发，那不是「关闭重试」而是
		// 「关闭转发」—— 归进这个统一的正数校验，不单开一条。
		{"retry_max_attempts", s.RetryMaxAttempts},
		// 日志的三项都必须为正。这里的 0 没有「不限」的语义 ——
		// 关日志用 request_log_enabled，而保留 0 条日志等于开着功能却
		// 把刚写的行立刻删掉，那不是任何人想要的配置。
		{"request_log_keep_count", s.RequestLogKeepCount},
		{"request_log_keep_days", s.RequestLogKeepDays},
		{"request_log_queue_size", s.RequestLogQueueSize},
	}
	for _, p := range positives {
		if p.val < 1 {
			return invalid("%s 必须为正数，收到 %d", p.name, p.val)
		}
	}
	if s.RetryMaxAttempts > MaxRetryAttempts {
		return invalid("retry_max_attempts 不得超过 %d，收到 %d。"+
			"它是一次客户端请求最多向上游发几次完整请求（每次都可能真的消耗 token），"+
			"填大不会报错，只会让每个失败请求悄悄放大成同样多次上游调用",
			MaxRetryAttempts, s.RetryMaxAttempts)
	}
	// 三个体积上限：0 = 不限（完整留档），负数无意义。
	//
	// 不设**上限**是刻意的：这几个值的作用就是封顶，给封顶再封一层顶
	// 只会让「我要完整留档」这个明确的意图变成一个需要绕过的限制。
	// 磁盘由 sample_keep_count / sample_keep_days 兜住。
	if s.SampleMaxBodyBytes < 0 || s.SampleRespHeadBytes < 0 || s.SampleRespTailBytes < 0 {
		return invalid("sample_max_body_bytes / sample_resp_head_bytes / " +
			"sample_resp_tail_bytes 不能为负（0 表示不限，即完整留档）")
	}

	// 总时长必须容得下首 Token，否则总超时会先触发，首 Token 超时形同虚设。
	if s.RealTotalSec < s.RealFirstTokenSec {
		return invalid("real_total_sec(%d) 不能小于 real_first_token_sec(%d)，"+
			"否则总超时先触发，首 Token 超时不起作用", s.RealTotalSec, s.RealFirstTokenSec)
	}
	if s.L2TotalSec < s.L2FirstTokenSec {
		return invalid("l2_total_sec(%d) 不能小于 l2_first_token_sec(%d)",
			s.L2TotalSec, s.L2FirstTokenSec)
	}
	return nil
}
