package probe

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// fuzzDecoderSpecs 覆盖每个 endpoint/protocol 组合。
//
// 全都跑：models 与 count_tokens 走专用结构，三个模型端点各有一套事件语法，
// 只 fuzz 其中一个的话另外几条分支的崩溃要等到生产才发现。
var fuzzDecoderSpecs = []DecoderSpec{
	{Endpoint: model.EndpointModels},
	{Endpoint: model.EndpointMessages, Protocol: model.ProtoAnthropic},
	{Endpoint: model.EndpointResponses, Protocol: model.ProtoOpenAIResponses},
	{Endpoint: model.EndpointChatCompletions, Protocol: model.ProtoOpenAIChat},
	{Endpoint: model.EndpointCountTokens, Protocol: model.ProtoAnthropic},
}

var fuzzWireFormats = []WireFormat{WireAuto, WireSSE, WireNDJSON, WireJSON}

// FuzzDecoderNeverPanicsOrGrowsUnbounded 是 P0-07 的安全网。
//
// Decoder 吃的是公益中转站的响应，也就是**任意字节**：截断的 UTF-8、半个
// 事件、嵌了 100 层的 JSON、只有 CR 没有 LF。这些不该崩，也不该让缓冲
// 无限长 —— 探活跑在调度器起的并发任务里，那里没有兜底恢复，一次 panic
// 会带崩整个网关进程，而一次无界增长会 OOM。
//
// 断言只有两条（不 panic、字节数有界）是刻意的：任意输入的**正确**解析结果
// 无法在 fuzz 里表达，那属于 fixture 测试。这里只保证「不管喂什么都不失控」。
func FuzzDecoderNeverPanicsOrGrowsUnbounded(f *testing.F) {
	seedFuzzCorpusFromFixtures(f)
	f.Add([]byte("event: ping\ndata: {}\n\n"), 1, 0)
	f.Add([]byte(`{"input_tokens":8}`), 0, 3)
	f.Add([]byte("{\"a\":1}\n{\"b\":2}\n"), 3, 2)
	f.Add([]byte("data: [DONE]\r\n\r\n"), 2, 1)
	f.Add([]byte{0xef, 0xbb, 0xbf, '{', '}'}, 0, 0)
	f.Add([]byte("data: {\"delta\":\"\xff\xfe\"}\n\n"), 1, 1)

	const (
		maxEventBytes = 1 << 12
		maxTotalBytes = 1 << 14
	)

	f.Fuzz(func(t *testing.T, body []byte, chunkSize int, selector int) {
		if chunkSize <= 0 {
			chunkSize = 1
		}
		if chunkSize > len(body)+1 {
			chunkSize = len(body) + 1
		}
		if selector < 0 {
			selector = -selector
		}

		spec := fuzzDecoderSpecs[selector%len(fuzzDecoderSpecs)]
		format := fuzzWireFormats[(selector/len(fuzzDecoderSpecs))%len(fuzzWireFormats)]

		decoder, err := NewDecoder(spec, format, maxEventBytes, maxTotalBytes)
		if err != nil {
			t.Fatalf("NewDecoder rejected a valid spec: %v", err)
		}

		for start := 0; start < len(body); start += chunkSize {
			end := min(start+chunkSize, len(body))
			if _, err := decoder.Feed(body[start:end]); err != nil {
				break
			}
		}
		_, _ = decoder.Finish()

		// 出错后继续喂不能让内部缓冲继续增长：一个已经判失败的流仍可能
		// 有大量在途字节，Executor 关闭连接前它们都会到达。
		for range 4 {
			_, _ = decoder.Feed(body)
			_, _ = decoder.Finish()
		}

		if seen := decoder.BytesSeen(); seen > maxTotalBytes {
			t.Fatalf("BytesSeen() = %d, want at most %d", seen, maxTotalBytes)
		}
	})
}

// seedFuzzCorpusFromFixtures 把真实抓包语料喂给 fuzz。
//
// 从 fixture 起步而不是纯随机：随机字节几乎永远进不到「合法事件的深处」，
// 而真实语料的**变异**才会命中那些分支（少一个引号的 delta、被截断的 usage）。
func seedFuzzCorpusFromFixtures(f *testing.F) {
	f.Helper()
	manifest, err := loadFixtureManifest("testdata")
	if err != nil {
		f.Fatalf("load fixture manifest: %v", err)
	}
	for index, fixture := range manifest.Cases {
		body, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(fixture.ResponseFile)))
		if err != nil {
			f.Fatalf("read %s: %v", fixture.ID, err)
		}
		f.Add(body, 1, index)
		f.Add(body, len(body), index)
	}
}
