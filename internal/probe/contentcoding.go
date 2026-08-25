package probe

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// ContentCodingLimits 限制压缩输入、解压输出和解码工作量。
type ContentCodingLimits struct {
	MaxEncodedBytes int64
	MaxDecodedBytes int64

	// MaxWorkUnits 是允许的 Read 次数上限，不是字节数。
	//
	// 必须与 MaxDecodedBytes 计不同的东西，否则它只是后者的别名。真正要防的是
	// 「一直返回 (0, nil) 的源」：那种流一个字节都不产出，字节预算永远不减，
	// 而 io.ReadAll 会原地空转 —— 实测每 2 秒十亿次。探活跑在调度器起的
	// goroutine 里，这比 panic 更糟：panic 至少会留下栈，空转只是把一个核吃满，
	// 看起来像「这个站很慢」。
	MaxWorkUnits int64
}

var (
	ErrUnknownContentEncoding   = errors.New("unknown content encoding")
	ErrEncodedBodyTooLarge      = errors.New("encoded body exceeds limit")
	ErrDecodedBodyTooLarge      = errors.New("decoded body exceeds limit")
	ErrContentEncodingTruncated = errors.New("content encoding is truncated")
	ErrMalformedContentEncoding = errors.New("malformed content encoding")
	ErrContentDecoderWorkBudget = errors.New("content decoder work budget exceeded")
)

const (
	defaultMaxEncodedBytes = 1 << 20
	defaultMaxDecodedBytes = 1 << 20
	defaultMaxCodingWork   = 1 << 20
)

// NewContentDecoder 返回一个有界只读解码器，不取得 src 的关闭所有权。
func NewContentDecoder(encoding string, src io.Reader, limits ContentCodingLimits) (io.ReadCloser, error) {
	if src == nil {
		return nil, fmt.Errorf("%w: nil source", ErrUnknownContentEncoding)
	}
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if encoding == "" {
		encoding = "identity"
	}
	if strings.Contains(encoding, ",") ||
		(encoding != "identity" && encoding != "gzip" && encoding != "br") {
		return nil, fmt.Errorf("%w: %s", ErrUnknownContentEncoding, encoding)
	}
	if limits.MaxEncodedBytes <= 0 {
		limits.MaxEncodedBytes = defaultMaxEncodedBytes
	}
	if limits.MaxDecodedBytes <= 0 {
		limits.MaxDecodedBytes = defaultMaxDecodedBytes
	}
	if limits.MaxWorkUnits <= 0 {
		limits.MaxWorkUnits = defaultMaxCodingWork
	}

	encoded := &limitedEncodedReader{src: src, limit: limits.MaxEncodedBytes}
	var decoded io.Reader = encoded
	var closeFn func() error
	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(encoded)
		if err != nil {
			return nil, wrapContentEncodingErr(encoding, err)
		}
		decoded = reader
		closeFn = reader.Close
	case "br":
		decoded = brotli.NewReader(encoded)
	}
	return &boundedContentReader{
		encoding:   encoding,
		encoded:    encoded,
		decoded:    decoded,
		closeFn:    closeFn,
		maxDecoded: limits.MaxDecodedBytes,
		maxWork:    limits.MaxWorkUnits,
	}, nil
}

type limitedEncodedReader struct {
	src     io.Reader
	limit   int64
	seen    int64
	overrun bool
}

func (r *limitedEncodedReader) Read(p []byte) (int, error) {
	if r.overrun {
		return 0, ErrEncodedBodyTooLarge
	}
	if r.seen >= r.limit {
		var one [1]byte
		n, err := r.src.Read(one[:])
		if n > 0 {
			r.overrun = true
			return 0, ErrEncodedBodyTooLarge
		}
		return 0, err
	}
	max := r.limit - r.seen
	if int64(len(p)) > max {
		p = p[:max]
	}
	n, err := r.src.Read(p)
	r.seen += int64(n)
	return n, err
}

type boundedContentReader struct {
	encoding   string
	encoded    *limitedEncodedReader
	decoded    io.Reader
	closeFn    func() error
	maxDecoded int64
	maxWork    int64
	decodedN   int64
	workN      int64
	finished   bool
	terminal   error
}

func (r *boundedContentReader) Read(p []byte) (int, error) {
	if r.terminal != nil {
		return 0, r.terminal
	}
	if r.finished {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.workN >= r.maxWork {
		return 0, r.fail(fmt.Errorf("%w: encoding=%s limit=%d", ErrContentDecoderWorkBudget,
			r.encoding, r.maxWork))
	}
	r.workN++

	// 额度用尽后仍要再读一次，只读 1 字节：一份**正好**等于上限的正文与一份
	// 真正超限的正文，区别只在「后面还有没有字节」。到额度就直接报超限会拒掉
	// 前者，而报出来是「解压输出超限」—— 与真正的解压炸弹无法区分。
	// 这与 encoded 侧的「到上限后再探一个字节」是同一套语义。
	atBudget := false
	if remaining := r.maxDecoded - r.decodedN; remaining <= 0 {
		atBudget = true
		p = p[:1]
	} else if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	n, err := r.decoded.Read(p)
	if n > 0 && atBudget {
		return 0, r.fail(fmt.Errorf("%w: encoding=%s limit=%d", ErrDecodedBodyTooLarge,
			r.encoding, r.maxDecoded))
	}
	r.decodedN += int64(n)
	if err != nil {
		if errors.Is(err, io.EOF) {
			r.finished = true
			if r.encoding != "identity" && r.encoded.overrun {
				return n, r.fail(ErrEncodedBodyTooLarge)
			}
			if r.encoding == "gzip" && r.encoded.seen == 0 {
				return n, r.fail(fmt.Errorf("%w: encoding=%s", ErrContentEncodingTruncated, r.encoding))
			}
			return n, io.EOF
		}
		if errors.Is(err, ErrEncodedBodyTooLarge) {
			return n, r.fail(err)
		}
		return n, r.fail(wrapContentEncodingErr(r.encoding, err))
	}
	return n, nil
}

// wrapContentEncodingErr 把压缩库的错误分成「流被截断」与「声明的编码与实际
// 字节不符」两类。
//
// 都报成截断的话，排查会从「连接为什么断了」开始，而真正该看的是「这个站的
// Content-Encoding 头是不是在撒谎」—— P0-08 对两者的处置也相反：截断是瞬时
// 故障可重试，声明不符是站点能力问题。
//
// compress/gzip 与 brotli 恰好都用 io.ErrUnexpectedEOF 表示「字节没给完」，
// 各自的具体错误（gzip: invalid header/checksum、brotli: CL_SPACE 等）表示
// 「给的字节根本不是这个格式」，所以一条规则就够，不需要按 encoding 分支。
func wrapContentEncodingErr(encoding string, err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: encoding=%s", ErrContentEncodingTruncated, encoding)
	}
	return fmt.Errorf("%w: encoding=%s", ErrMalformedContentEncoding, encoding)
}

func (r *boundedContentReader) Close() error {
	if r.closeFn != nil {
		return r.closeFn()
	}
	return nil
}

func (r *boundedContentReader) fail(err error) error {
	if r.terminal == nil {
		r.terminal = err
	}
	return r.terminal
}
