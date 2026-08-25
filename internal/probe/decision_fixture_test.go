package probe

// fixture 驱动的 Decision 回归（P0-08 的验收条件：manifest 的 expected
// decision 100% 通过）。
//
// 这里把 Decoder 与 Classifier 串起来跑真实抓包字节，而 decision_test.go 用
// 手写事件覆盖分支。两者都要有：手写事件能构造出真实语料里没有的边界
// （负 token、过去的 HTTP-date），而 fixture 证明「真站发来的字节确实会走到
// 我们以为的那条分支」—— 手写事件测不出这一点，因为事件是我们自己编的。

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func fixtureEndpointKind(t *testing.T, fixture fixtureCase) model.EndpointKind {
	t.Helper()
	kind := fixtureDecoderSpec(t, fixture).Endpoint
	if !kind.Valid() {
		t.Fatalf("fixture %q has invalid endpoint", fixture.ID)
	}
	return kind
}

// classifyFixture 用真实 fixture 字节跑一次完整观察。
//
// 按 manifest 声明的 chunk plan 喂：Decision 不能取决于网络怎么切包。
// 若某个 plan 下少收到一个语义事件，结论就会从 supported 变成 fake_alive ——
// 而那种错误在生产里表现为「这个站时好时坏」，完全无法定位。
func classifyFixture(t *testing.T, fixture fixtureCase, chunks [][]byte) Decision {
	t.Helper()
	endpoint := fixtureEndpointKind(t, fixture)
	classifier := NewResponseClassifier(ObserveProbe, endpoint, fixture.Status,
		fixtureResponseHeader(fixture), headerAt)

	decoder, err := NewDecoder(fixtureDecoderSpec(t, fixture), WireFormat(fixture.WireFormat),
		256<<10, 1<<20)
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}

	for _, chunk := range chunks {
		events, feedErr := decoder.Feed(chunk)
		for _, event := range events {
			if _, final := classifier.Observe(event); final {
				// Probe 拿到证据就断流，剩下的字节不再喂 —— 这正是生产行为，
				// 而「测试里读完整个 body」会让「首个语义后取消」这条路径
				// 在回归里从来没被走过。
				return classifier.Finish(nil, ErrProbeCanceledAfterSemantic)
			}
		}
		if feedErr != nil {
			return classifier.Finish(feedErr, nil)
		}
	}

	events, finishErr := decoder.Finish()
	for _, event := range events {
		if _, final := classifier.Observe(event); final {
			return classifier.Finish(nil, ErrProbeCanceledAfterSemantic)
		}
	}
	return classifier.Finish(finishErr, nil)
}

// fixtureResponseHeader 只取 Classifier 真的会读的头。
//
// 目前只有 Retry-After。刻意不把 manifest 的全部头都塞进去：Classifier 读了
// 什么就该在这里显式列出，一股脑传进去会让「它到底依赖哪些头」变得看不出来。
func fixtureResponseHeader(fixture fixtureCase) map[string][]string {
	header := map[string][]string{}
	for name, values := range fixture.Headers {
		if len(values) > 0 && equalFoldASCIIFixture(name, "retry-after") {
			header["Retry-After"] = values
		}
	}
	if len(header) == 0 {
		return nil
	}
	return header
}

func equalFoldASCIIFixture(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := 0; index < len(left); index++ {
		if lowerASCII(left[index]) != lowerASCII(right[index]) {
			return false
		}
	}
	return true
}

func lowerASCII(character byte) byte {
	if character >= 'A' && character <= 'Z' {
		return character + ('a' - 'A')
	}
	return character
}

// P0-01 的 19 个 fixture 必须 100% 得到 manifest 声明的 Decision。
//
// 这是 P0-08 的验收条件本身。fixture 覆盖的是真实站点上实测过的形态：
// agentRouter 的 error:null、output_tokens:0、多行 SSE、200 流内错误、
// context-1m 配方要求 —— 每一个都曾让旧路径误判。
func TestClassifierMatchesManifestDecisionsAcrossChunkPlans(t *testing.T) {
	manifest, err := loadFixtureManifest("testdata")
	if err != nil {
		t.Fatalf("load fixture manifest: %v", err)
	}

	for _, fixture := range manifest.Cases {
		t.Run(fixture.ID, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(fixture.ResponseFile)))
			if err != nil {
				t.Fatal(err)
			}

			_, chunks, err := splitFixtureResponse(body, fixture.ChunkPlan)
			if err != nil {
				t.Fatal(err)
			}
			planned := classifyFixture(t, fixture, chunks)
			assertFixtureDecision(t, fixture, planned)

			// 同一份字节整块喂必须得到同一个 Decision。
			_, wholeChunks, err := splitFixtureResponse(body, fixtureChunkPlan{Name: "whole"})
			if err != nil {
				t.Fatal(err)
			}
			whole := classifyFixture(t, fixture, wholeChunks)
			if whole != planned {
				t.Fatalf("chunk plan changed the decision:\nplanned = %+v\nwhole   = %+v", planned, whole)
			}

			// 逐字节也一样。这是最容易暴露状态机缺陷的切法：每个事件都跨
			// 多次 Feed，而 Classifier 的中间态若依赖「一次 Feed 一个事件」
			// 就会在这里塌掉。
			_, singleByte, err := splitFixtureResponse(body, fixtureChunkPlan{Name: "single_byte"})
			if err != nil {
				t.Fatal(err)
			}
			if got := classifyFixture(t, fixture, singleByte); got != planned {
				t.Fatalf("single-byte feed changed the decision:\nplanned = %+v\ngot     = %+v", planned, got)
			}
		})
	}
}

func assertFixtureDecision(t *testing.T, fixture fixtureCase, decision Decision) {
	t.Helper()
	if decision.Success != fixture.ExpectedDecision.Success {
		t.Errorf("Success = %v, want %v", decision.Success, fixture.ExpectedDecision.Success)
	}
	if got, want := string(decision.Capability), fixture.ExpectedDecision.Capability; got != want {
		t.Errorf("Capability = %q, want %q", got, want)
	}
	if got, want := string(decision.ErrorClass), fixture.ExpectedDecision.ErrorClass; got != want {
		t.Errorf("ErrorClass = %q, want %q", got, want)
	}
	if !decision.Final {
		t.Error("Final = false, want true")
	}
	// 每个 fixture 都拿到了响应头（manifest 要求声明 status 与 headers），
	// 所以站一定可达 —— 这正是 §8.9 与旧路径最大的分歧：业务错误绝不能
	// 表达成「网络不可达」。
	if !decision.Reachable {
		t.Error("Reachable = false; every fixture has a real HTTP status")
	}
}

// fixture 的 Decision 不含任何上游原文。
//
// §4.6 要求 RedactedDetail 只由结构化枚举拼装。fixture 是真实抓包，正文里
// 有真实的 error message（"context-1m beta header is required" 之类）——
// 若哪条分支把 message 拼进了详情，这里会逮到，而手写事件测不出来
// （手写事件压根没有 message 字段可泄漏）。
func TestFixtureDecisionsNeverLeakUpstreamProse(t *testing.T) {
	manifest, err := loadFixtureManifest("testdata")
	if err != nil {
		t.Fatalf("load fixture manifest: %v", err)
	}

	for _, fixture := range manifest.Cases {
		t.Run(fixture.ID, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(fixture.ResponseFile)))
			if err != nil {
				t.Fatal(err)
			}
			_, chunks, err := splitFixtureResponse(body, fixture.ChunkPlan)
			if err != nil {
				t.Fatal(err)
			}
			detail := classifyFixture(t, fixture, chunks).RedactedDetail
			if detail == "" {
				return
			}
			// 详情里的每一段都必须是结构化字段值，也就是不含空格的短标识符。
			// 上游的 message 是散文，一定带空格 —— 这条判据挡的正是它。
			for _, character := range detail {
				if character == ' ' {
					t.Fatalf("RedactedDetail %q contains prose (a space); "+
						"only structured type/code/param values are allowed", detail)
				}
			}
			if len(detail) > maxRedactedDetail {
				t.Fatalf("RedactedDetail length = %d, want at most %d", len(detail), maxRedactedDetail)
			}
		})
	}
}

// Classifier 不读时钟。
//
// §4.6 明文禁止（「禁止 classifier 内部调用 time.Now()」）。判据是同一份
// fixture 在两个相隔很远的 headerAt 下，除 RetryAfterUntilMS 外完全一致 ——
// 若哪里读了真实时钟，那个字段之外的东西也会随执行时刻漂移。
//
// 这条守的是一个具体后果：Executor 的 Clock 与真实流量观察器的 TryHeaders
// 时间必须与 Decision 同一口径，各读一次 time.Now() 会让「同一次响应」在
// execution 行里出现两个互相矛盾的时间，而那种不一致在事后无法分辨。
func TestClassifierDecisionsDoNotDependOnWallClock(t *testing.T) {
	manifest, err := loadFixtureManifest("testdata")
	if err != nil {
		t.Fatalf("load fixture manifest: %v", err)
	}

	distantPast := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, fixture := range manifest.Cases {
		t.Run(fixture.ID, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(fixture.ResponseFile)))
			if err != nil {
				t.Fatal(err)
			}
			_, chunks, err := splitFixtureResponse(body, fixture.ChunkPlan)
			if err != nil {
				t.Fatal(err)
			}

			first := classifyFixture(t, fixture, chunks)
			second := classifyFixtureAt(t, fixture, chunks, distantPast)
			first.RetryAfterUntilMS, second.RetryAfterUntilMS = 0, 0
			if first != second {
				t.Fatalf("decision depends on the injected clock:\nheaderAt = %+v\npast     = %+v",
					first, second)
			}
		})
	}
}

// classifyFixtureAt 与 classifyFixture 相同，只是换一个注入时刻。
func classifyFixtureAt(t *testing.T, fixture fixtureCase, chunks [][]byte, at time.Time) Decision {
	t.Helper()
	classifier := NewResponseClassifier(ObserveProbe, fixtureEndpointKind(t, fixture),
		fixture.Status, fixtureResponseHeader(fixture), at)
	decoder, err := NewDecoder(fixtureDecoderSpec(t, fixture), WireFormat(fixture.WireFormat),
		256<<10, 1<<20)
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}
	for _, chunk := range chunks {
		events, feedErr := decoder.Feed(chunk)
		for _, event := range events {
			if _, final := classifier.Observe(event); final {
				return classifier.Finish(nil, ErrProbeCanceledAfterSemantic)
			}
		}
		if feedErr != nil {
			return classifier.Finish(feedErr, nil)
		}
	}
	events, finishErr := decoder.Finish()
	for _, event := range events {
		if _, final := classifier.Observe(event); final {
			return classifier.Finish(nil, ErrProbeCanceledAfterSemantic)
		}
	}
	return classifier.Finish(finishErr, nil)
}
