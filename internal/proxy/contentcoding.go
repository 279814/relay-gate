package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"

	"github.com/279814/relay-gate/internal/transform"
)

// normalizeContentEncoding returns the single Content-Encoding token (lowercased),
// or "" when absent / identity. Multi-coding values are returned as-is (unsupported).
func normalizeContentEncoding(h string) string {
	enc := strings.ToLower(strings.TrimSpace(h))
	if enc == "" || enc == "identity" {
		return ""
	}
	return enc
}

// contentEncodingDecodable reports encodings the transform path can decode
// before applying body / SSE rules.
func contentEncodingDecodable(enc string) bool {
	switch enc {
	case "gzip", "deflate", "br":
		return true
	default:
		return false
	}
}

// decodeTransformBody expands a buffered upstream body for transform apply.
// limit is the maximum decoded size (typically transform.MaxBodyBuffer).
func decodeTransformBody(enc string, body []byte, limit int) ([]byte, error) {
	if limit <= 0 {
		limit = transform.MaxBodyBuffer
	}
	r, err := newContentEncodingReader(enc, body)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out bytes.Buffer
	n, err := io.Copy(&out, io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("decode %s body: %w", enc, err)
	}
	if n > int64(limit) {
		return nil, fmt.Errorf("decoded %s body exceeds %d byte buffer", enc, limit)
	}
	return out.Bytes(), nil
}

// newContentEncodingReader returns a decoder over a buffered encoded body.
// Caller must Close the result.
func newContentEncodingReader(enc string, body []byte) (io.ReadCloser, error) {
	src := bytes.NewReader(body)
	switch enc {
	case "gzip":
		zr, err := gzip.NewReader(src)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		return zr, nil
	case "deflate":
		// RFC 9110 deflate is zlib-wrapped; some peers send raw flate.
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			return zr, nil
		}
		return flate.NewReader(bytes.NewReader(body)), nil
	case "br":
		return io.NopCloser(brotli.NewReader(src)), nil
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", enc)
	}
}

// newContentEncodingStream wraps a live upstream reader for SSE transform.
// Caller must Close the result; it does not close src.
func newContentEncodingStream(enc string, src io.Reader) (io.ReadCloser, error) {
	switch enc {
	case "gzip":
		zr, err := gzip.NewReader(src)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		return zr, nil
	case "deflate":
		// Streaming path cannot safely fall back to raw flate after a failed
		// zlib header read (bytes already consumed). Buffered path handles both.
		zr, err := zlib.NewReader(src)
		if err != nil {
			return nil, fmt.Errorf("deflate: %w", err)
		}
		return zr, nil
	case "br":
		return io.NopCloser(brotli.NewReader(src)), nil
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", enc)
	}
}

// responseRulesTouchBody reports whether published rules read or mutate the
// response body (non-SSE). Header/status-only rules leave compression alone.
func responseRulesTouchBody(c *transform.Compiled) bool {
	if c == nil {
		return false
	}
	for _, rule := range c.Version.Rules {
		switch rule.Kind {
		case transform.KindReplaceBytes, transform.KindSetJSONPointer,
			transform.KindJSONPatchAdd, transform.KindJSONPatchRemove,
			transform.KindJSONPatchCopy, transform.KindBodyTemplate:
			return true
		}
	}
	return false
}

// responseRulesTouchSSE reports whether published rules rewrite SSE events.
func responseRulesTouchSSE(c *transform.Compiled) bool {
	if c == nil {
		return false
	}
	for _, rule := range c.Version.Rules {
		switch rule.Kind {
		case transform.KindSSEMatch, transform.KindSSEAppendEnd:
			return true
		}
	}
	return false
}
