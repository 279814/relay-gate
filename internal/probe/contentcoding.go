package probe

import (
	"io"

	"github.com/279814/relay-gate/internal/protocol"
)

// Content coding is shared with bounded passive diagnostics; health callers
// retain the same API and error identities.
type ContentCodingLimits = protocol.ContentCodingLimits

var (
	ErrUnknownContentEncoding   = protocol.ErrUnknownContentEncoding
	ErrEncodedBodyTooLarge      = protocol.ErrEncodedBodyTooLarge
	ErrDecodedBodyTooLarge      = protocol.ErrDecodedBodyTooLarge
	ErrContentEncodingTruncated = protocol.ErrContentEncodingTruncated
	ErrMalformedContentEncoding = protocol.ErrMalformedContentEncoding
	ErrContentDecoderWorkBudget = protocol.ErrContentDecoderWorkBudget
)

func NewContentDecoder(encoding string, src io.Reader, limits ContentCodingLimits) (io.ReadCloser, error) {
	return protocol.NewContentDecoder(encoding, src, limits)
}
