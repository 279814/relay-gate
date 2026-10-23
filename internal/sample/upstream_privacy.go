package sample

import (
	"bytes"
	"io"
	"os"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/protocol"
)

// Validation is a bounded read of the existing original body, never a second
// stored response or re-encoding. Failure preserves metadata and omits bytes.
const maxRawSampleEncoded = 16 << 20
const maxRawSampleDecoded = 64 << 20

func validateOriginalResponsePrivacy(s *model.Sample) {
	if s == nil {
		return
	}
	keys := s.ResponsePrivacyKeys
	s.ResponsePrivacyKeys = nil
	for _, a := range s.Attempts {
		if a == nil || (a.ResponseCaptureView != "upstream_response" && a.ResponseCaptureView != "upstream_attempt_prefix") {
			continue
		}
		encoding := strings.ToLower(strings.TrimSpace(a.RespHeaders.Get("Content-Encoding")))
		if encoding == "" || encoding == "identity" {
			continue
		}
		reason := encodedResponseOmission(a, encoding, keys)
		if reason == "" {
			continue
		}
		model.RemoveSpillFile(a.RespBodyFile)
		a.RespBody, a.RespBodyFile = nil, ""
		a.Truncated |= model.TruncRespBody
		a.ResponseCaptureView, a.Metadata.ResponseView = reason, reason
	}
	if len(s.Attempts) > 0 {
		a := s.Attempts[len(s.Attempts)-1]
		s.RespBody, s.RespBodyFile = a.RespBody, ""
		s.Metadata = a.Metadata
		s.Truncated = (s.Truncated &^ model.TruncRespBody) | (a.Truncated & model.TruncRespBody)
	}
}

func encodedResponseOmission(a *model.SampleAttempt, encoding string, keys []string) string {
	if a.Truncated.Has(model.TruncRespBody) {
		return "omitted_unverified"
	}
	usable := make([]string, 0, len(keys))
	maxK := 0
	for _, key := range keys {
		if len(key) < model.MinRedactableKeyLen {
			continue
		}
		if len(key) > 4096 {
			return "omitted_unverified"
		}
		usable = append(usable, key)
		maxK = max(maxK, len(key)*6)
	}
	if len(usable) == 0 {
		return ""
	}
	var src io.Reader = bytes.NewReader(a.RespBody)
	if a.RespBodyFile != "" {
		path, err := model.ConfinedSpillPath(a.RespBodyFile)
		if err != nil {
			return "omitted_unverified"
		}
		file, err := os.Open(path)
		if err != nil {
			return "omitted_unverified"
		}
		defer file.Close()
		src = file
	}
	decoded, err := protocol.NewContentDecoder(encoding, src, protocol.ContentCodingLimits{MaxEncodedBytes: maxRawSampleEncoded, MaxDecodedBytes: maxRawSampleDecoded, MaxWorkUnits: 4096})
	if err != nil {
		return "omitted_unverified"
	}
	defer decoded.Close()
	hit, err := readerContainsAny(decoded, usable, maxK)
	if hit {
		return "omitted_secret"
	}
	if err != nil {
		return "omitted_unverified"
	}
	return ""
}
