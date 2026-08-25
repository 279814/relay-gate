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
	MaxWorkUnits    int64
}

var (
	ErrUnknownContentEncoding   = errors.New("unknown content encoding")
	ErrEncodedBodyTooLarge      = errors.New("encoded body exceeds limit")
	ErrDecodedBodyTooLarge      = errors.New("decoded body exceeds limit")
	ErrContentEncodingTruncated = errors.New("content encoding is truncated")
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
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, fmt.Errorf("%w: gzip", ErrContentEncodingTruncated)
			}
			return nil, fmt.Errorf("%w: gzip", ErrContentEncodingTruncated)
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
	remaining := r.maxDecoded - r.decodedN
	if remaining <= 0 {
		return 0, r.fail(fmt.Errorf("%w: encoding=%s limit=%d", ErrDecodedBodyTooLarge,
			r.encoding, r.maxDecoded))
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	workRemaining := r.maxWork - r.workN
	if workRemaining <= 0 {
		return 0, r.fail(fmt.Errorf("%w: encoding=%s limit=%d", ErrContentDecoderWorkBudget,
			r.encoding, r.maxWork))
	}
	if int64(len(p)) > workRemaining {
		p = p[:workRemaining]
	}
	n, err := r.decoded.Read(p)
	r.decodedN += int64(n)
	r.workN += int64(n)
	if err != nil {
		if errors.Is(err, io.EOF) {
			r.finished = true
			if r.encoding != "identity" && r.encoded.overrun {
				return n, r.fail(ErrEncodedBodyTooLarge)
			}
			if r.encoding == "gzip" && r.encoded.seen == 0 {
				return n, r.fail(ErrContentEncodingTruncated)
			}
			return n, io.EOF
		}
		if errors.Is(err, ErrEncodedBodyTooLarge) {
			return n, r.fail(err)
		}
		if errors.Is(err, io.ErrUnexpectedEOF) || r.encoding == "gzip" {
			return n, r.fail(fmt.Errorf("%w: encoding=%s", ErrContentEncodingTruncated, r.encoding))
		}
		return n, r.fail(err)
	}
	if n == 0 {
		return 0, nil
	}
	if r.decodedN >= r.maxDecoded {
		return n, r.fail(fmt.Errorf("%w: encoding=%s limit=%d", ErrDecodedBodyTooLarge,
			r.encoding, r.maxDecoded))
	}
	if r.workN >= r.maxWork {
		return n, r.fail(fmt.Errorf("%w: encoding=%s limit=%d", ErrContentDecoderWorkBudget,
			r.encoding, r.maxWork))
	}
	return n, nil
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
