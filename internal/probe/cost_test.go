package probe

import (
	"github.com/279814/relay-gate/internal/model"
	"testing"
)

func TestEstimateL2Tokens_ScalesWithMaxTokens(t *testing.T) {
	// max_tokens 是输出上界，探活的开销主要由它决定 ——
	// 这正是「策略是否过激」要看的东西。
	small := estimateL2Tokens(&model.ModelName{ProbePrompt: "1+1=?", ProbeMaxTokens: 1})
	big := estimateL2Tokens(&model.ModelName{ProbePrompt: "1+1=?", ProbeMaxTokens: 100})
	if big <= small {
		t.Errorf("max_tokens 大的估算应更大：small=%d big=%d", small, big)
	}
	if big-small != 99 {
		t.Errorf("差值应等于 max_tokens 之差，得到 %d", big-small)
	}
}

func TestEstimateL2Tokens_UsesDefaultsForZeroValues(t *testing.T) {
	// 与 probePrompt 的兜底保持一致：prompt 空用 "1+1=?"，max_tokens 为 0 用 1。
	// 两处不一致的话，估算的是一个根本没发出去的请求。
	got := estimateL2Tokens(&model.ModelName{})
	want := estimateL2Tokens(&model.ModelName{ProbePrompt: defaultProbePrompt, ProbeMaxTokens: 1})
	if got != want {
		t.Errorf("零值应回落到与显式默认值相同的估算：%d vs %d", got, want)
	}
}

func TestEstimatePromptTokens_CJKIsDenserThanASCII(t *testing.T) {
	// CJK 在真实 tokenizer 里约每字 1.5 个 token，ASCII 约每 4 字符 1 个。
	// 三个汉字应当明显多于三个字母，而不是相等 ——
	// 早先这里用无条件 len(rune)/4，把两者都算成同一个数。
	cn := estimatePromptTokens("你好吗")
	en := estimatePromptTokens("abc")
	if cn <= en {
		t.Errorf("三个汉字应比三个字母估得多：cn=%d en=%d", cn, en)
	}
	if cn != 4 { // 3 × 1.5 = 4.5 → 4
		t.Errorf("三个汉字应估 4 个 token，得到 %d", cn)
	}
}

func TestEstimatePromptTokens_ShortCJKIsNotZero(t *testing.T) {
	// 这是 review 时实测抓到的 bug：无条件 len(rune)/4 让 "你好" 算成 0 ——
	// 整数除法在短 CJK 串上直接截断到零，而 CJK 恰恰是密度**最高**的输入，
	// 方向正好反。probe_prompt 是 UI 可改的配置项（§4.7），中文完全可达。
	if got := estimatePromptTokens("你好"); got < 3 {
		t.Errorf("两个汉字至少应估 3 个 token（2 × 1.5），得到 %d", got)
	}
}

func TestEstimatePromptTokens_NonEmptyNeverZero(t *testing.T) {
	// 任何非空 prompt 都会产生 token。返回 0 会让「今日估算 token」
	// 偏小，而偏小是成本估算最不该出的方向。
	for _, p := range []string{"a", "?", "1", "你", " "} {
		if got := estimatePromptTokens(p); got < 1 {
			t.Errorf("prompt %q 的估算不该是 0，得到 %d", p, got)
		}
	}
}

func TestEstimatePromptTokens_EmptyIsHandledByCaller(t *testing.T) {
	// 空 prompt 由 estimateL2Tokens 回落到 defaultProbePrompt，与渲染侧
	// （probePrompt）一致。直接问 estimatePromptTokens("") 时返回 1 而不是 0 ——
	// 那是下限保护，不是一个有意义的值，所以这里只断言它不会 panic 或返回负数。
	if got := estimatePromptTokens(""); got < 0 {
		t.Errorf("不该返回负数，得到 %d", got)
	}
}
