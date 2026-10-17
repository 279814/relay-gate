package probe

import "github.com/279814/relay-gate/internal/protocol"

// Probe and real forwarding use one incremental wire implementation. These
// aliases preserve the existing probe API without another parser or ruleset.
type (
	WireFormat    = protocol.WireFormat
	EventKind     = protocol.EventKind
	ProtocolEvent = protocol.ProtocolEvent
	DecoderSpec   = protocol.DecoderSpec
	Decoder       = protocol.Decoder
)

const (
	WireAuto         = protocol.WireAuto
	WireSSE          = protocol.WireSSE
	WireNDJSON       = protocol.WireNDJSON
	WireJSON         = protocol.WireJSON
	EventMetadata    = protocol.EventMetadata
	EventSemantic    = protocol.EventSemantic
	EventUsage       = protocol.EventUsage
	EventModelList   = protocol.EventModelList
	EventProtocolEnd = protocol.EventProtocolEnd
	EventRemoteError = protocol.EventRemoteError
	EventKeepalive   = protocol.EventKeepalive
)

var (
	ErrInvalidDecoderSpec = protocol.ErrInvalidDecoderSpec
	ErrUnknownWireFormat  = protocol.ErrUnknownWireFormat
	ErrMalformedWire      = protocol.ErrMalformedWire
	ErrIncompleteWire     = protocol.ErrIncompleteWire
	ErrTrailingJSON       = protocol.ErrTrailingJSON
	ErrEventTooLarge      = protocol.ErrEventTooLarge
	ErrDecoderWorkBudget  = protocol.ErrDecoderWorkBudget
	ErrDecoderFinished    = protocol.ErrDecoderFinished
)

func NewDecoder(spec DecoderSpec, format WireFormat, maxEventBytes, maxTotalBytes int64) (Decoder, error) {
	return protocol.NewDecoder(spec, format, maxEventBytes, maxTotalBytes)
}

func DetectWireFormat(contentType string, prefix []byte) WireFormat {
	return protocol.DetectWireFormat(contentType, prefix)
}
