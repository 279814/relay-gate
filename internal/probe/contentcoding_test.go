package probe

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

func gzipBytes(t *testing.T, input []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func brotliBytes(input []byte) []byte {
	var out bytes.Buffer
	writer := brotli.NewWriter(&out)
	_, _ = writer.Write(input)
	_ = writer.Close()
	return out.Bytes()
}

func readAllContent(t *testing.T, encoding string, body []byte, limits ContentCodingLimits) ([]byte, error) {
	t.Helper()
	reader, err := NewContentDecoder(encoding, bytes.NewReader(body), limits)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func TestContentDecoderIdentityGzipAndBrotliProduceSameBytes(t *testing.T) {
	want := []byte("decoded probe response: 2")
	cases := []struct {
		name     string
		encoding string
		body     []byte
	}{
		{"identity", "", want},
		{"identity explicit", "identity", want},
		{"gzip", "gzip", gzipBytes(t, want)},
		{"brotli", "br", brotliBytes(want)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readAllContent(t, tc.encoding, tc.body, ContentCodingLimits{
				MaxEncodedBytes: 1 << 20,
				MaxDecodedBytes: 1 << 20,
				MaxWorkUnits:    1 << 20,
			})
			if err != nil {
				t.Fatalf("read decoded body: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("decoded = %q, want %q", got, want)
			}
		})
	}
}

func TestContentDecoderRejectsUnknownAndMultipleEncodings(t *testing.T) {
	for _, encoding := range []string{"deflate", "gzip, br", "gzip,identity"} {
		t.Run(strings.ReplaceAll(encoding, ",", "_"), func(t *testing.T) {
			_, err := NewContentDecoder(encoding, strings.NewReader("body"), ContentCodingLimits{})
			if !errors.Is(err, ErrUnknownContentEncoding) {
				t.Fatalf("NewContentDecoder(%q) = %v, want ErrUnknownContentEncoding", encoding, err)
			}
		})
	}
}

func TestContentDecoderRejectsEncodedInputBeyondLimit(t *testing.T) {
	_, err := readAllContent(t, "identity", []byte("12345"), ContentCodingLimits{
		MaxEncodedBytes: 4,
		MaxDecodedBytes: 100,
		MaxWorkUnits:    100,
	})
	if !errors.Is(err, ErrEncodedBodyTooLarge) {
		t.Fatalf("read error = %v, want ErrEncodedBodyTooLarge", err)
	}
}

func TestContentDecoderRejectsDecodedOutputBeyondLimit(t *testing.T) {
	compressed := gzipBytes(t, []byte(strings.Repeat("x", 128)))
	_, err := readAllContent(t, "gzip", compressed, ContentCodingLimits{
		MaxEncodedBytes: 1 << 20,
		MaxDecodedBytes: 32,
		MaxWorkUnits:    1 << 20,
	})
	if !errors.Is(err, ErrDecodedBodyTooLarge) {
		t.Fatalf("read error = %v, want ErrDecodedBodyTooLarge", err)
	}
}

// 正好等于上限的正文必须放行。
//
// 这条边界很容易写成「读完就检查 decodedN >= maxDecoded」，而那样一份恰好
// 等于上限的正文会被拒，报出来是「解压输出超限」—— 与真正的解压炸弹无法区分。
// encoded 侧已经是「到上限后再探一个字节」的语义，decoded 侧必须一致。
//
// identity 与 gzip 都要测：gzip 会把最后一批数据与 io.EOF 一起返回，于是提前
// 走进 EOF 分支、绕过读后检查；而 bytes.Reader 是先 (n, nil) 再 (0, EOF)。
// 只测 gzip 的话这条边界根本走不到，断言看着有覆盖其实没有。
func TestContentDecoderAcceptsBodyExactlyAtDecodedAndWorkLimit(t *testing.T) {
	want := []byte(strings.Repeat("x", 64))
	cases := []struct {
		name     string
		encoding string
		body     []byte
	}{
		{"identity", "identity", want},
		{"gzip", "gzip", gzipBytes(t, want)},
		{"brotli", "br", brotliBytes(want)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readAllContent(t, tc.encoding, tc.body, ContentCodingLimits{
				MaxEncodedBytes: 1 << 20,
				MaxDecodedBytes: int64(len(want)),
				MaxWorkUnits:    int64(len(want)),
			})
			if err != nil {
				t.Fatalf("body exactly at the limit was rejected: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("decoded = %q, want %q", got, want)
			}
		})
	}
}

// 「站点声明的编码与实际字节不符」和「压缩流被截断」是两件事。
//
// 都报成截断的话，排查会从「连接为什么断了」开始，而真正该看的是
// 「这个站的 Content-Encoding 头是不是在撒谎」—— P0-08 对两者的处置也相反：
// 截断是瞬时故障可重试，声明不符是站点能力问题。
//
// gzip 和 br 都要测：只测 gzip 的话，一个「br 分支就报截断」的实现也能过，
// 而那正好把 br 的两种失败合并成了一种。
func TestContentDecoderSeparatesMalformedEncodingFromTruncation(t *testing.T) {
	limits := ContentCodingLimits{
		MaxEncodedBytes: 1 << 20,
		MaxDecodedBytes: 1 << 20,
		MaxWorkUnits:    1 << 20,
	}
	payload := []byte(strings.Repeat("mislabeled response ", 8))
	cases := []struct {
		name     string
		encoding string
		body     []byte
	}{
		{"brotli bytes labelled gzip", "gzip", brotliBytes(payload)},
		{"gzip bytes labelled brotli", "br", gzipBytes(t, payload)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readAllContent(t, tc.encoding, tc.body, limits)
			if !errors.Is(err, ErrMalformedContentEncoding) {
				t.Fatalf("read error = %v, want ErrMalformedContentEncoding", err)
			}
			if errors.Is(err, ErrContentEncodingTruncated) {
				t.Fatalf("a mislabeled encoding must not be reported as truncation: %v", err)
			}
		})
	}
}

// br 的截断也要走同一层，否则「identity/gzip/br 共用一层」只是口号：
// 只给 gzip 测截断的话，br 分支静默返回原始库错误，上层拿不到具名错误。
func TestContentDecoderRejectsTruncatedBrotliBody(t *testing.T) {
	compressed := brotliBytes([]byte(strings.Repeat("truncated brotli response ", 8)))
	_, err := readAllContent(t, "br", compressed[:len(compressed)-2], ContentCodingLimits{
		MaxEncodedBytes: 1 << 20,
		MaxDecodedBytes: 1 << 20,
		MaxWorkUnits:    1 << 20,
	})
	if !errors.Is(err, ErrContentEncodingTruncated) {
		t.Fatalf("read error = %v, want ErrContentEncodingTruncated", err)
	}
}

func TestContentDecoderRejectsTruncatedCompressedBody(t *testing.T) {
	compressed := gzipBytes(t, []byte("truncated compressed response"))
	compressed = compressed[:len(compressed)-2]
	_, err := readAllContent(t, "gzip", compressed, ContentCodingLimits{
		MaxEncodedBytes: 1 << 20,
		MaxDecodedBytes: 1 << 20,
		MaxWorkUnits:    1 << 20,
	})
	if !errors.Is(err, ErrContentEncodingTruncated) {
		t.Fatalf("read error = %v, want ErrContentEncodingTruncated", err)
	}
}

// stallingReader 永远返回 (0, nil)：既不出错也不产出字节。
// 真实来源是一个建立了连接但迟迟不发正文的上游。
type stallingReader struct{}

func (stallingReader) Read([]byte) (int, error) { return 0, nil }

// 一直返回 (0, nil) 的源必须被工作预算截断。
//
// 这是 MaxWorkUnits 存在的理由：这种流一个字节都不产出，所以字节预算永远
// 不减，而 io.ReadAll 会原地空转（实测每 2 秒十亿次）。探活跑在调度器起的
// goroutine 里，这比 panic 更糟 —— panic 至少留下栈，空转只是把一个核吃满，
// 看起来像「这个站很慢」。
func TestContentDecoderStopsAReaderThatNeverMakesProgress(t *testing.T) {
	reader, err := NewContentDecoder("identity", stallingReader{}, ContentCodingLimits{
		MaxEncodedBytes: 1 << 20,
		MaxDecodedBytes: 1 << 20,
		MaxWorkUnits:    16,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrContentDecoderWorkBudget) {
		t.Fatalf("read error = %v, want ErrContentDecoderWorkBudget", err)
	}
}

func TestContentDecoderRejectsWorkBudgetExceeded(t *testing.T) {
	// 预算是 Read 次数：identity 下每次最多读 1 字节，所以 2 次预算读不完 6 字节。
	reader, err := NewContentDecoder("identity", strings.NewReader("123456"), ContentCodingLimits{
		MaxEncodedBytes: 100,
		MaxDecodedBytes: 100,
		MaxWorkUnits:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var one [1]byte
	var readErr error
	for range 8 {
		if _, readErr = reader.Read(one[:]); readErr != nil {
			break
		}
	}
	if !errors.Is(readErr, ErrContentDecoderWorkBudget) {
		t.Fatalf("read error = %v, want ErrContentDecoderWorkBudget", readErr)
	}
}
