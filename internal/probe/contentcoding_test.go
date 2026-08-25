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

func TestContentDecoderRejectsWorkBudgetExceeded(t *testing.T) {
	_, err := readAllContent(t, "identity", []byte("123456"), ContentCodingLimits{
		MaxEncodedBytes: 100,
		MaxDecodedBytes: 100,
		MaxWorkUnits:    3,
	})
	if !errors.Is(err, ErrContentDecoderWorkBudget) {
		t.Fatalf("read error = %v, want ErrContentDecoderWorkBudget", err)
	}
}
