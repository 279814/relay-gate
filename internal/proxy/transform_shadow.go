package proxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/transform"
)

// shadowRequest runs the bound shadow version on a side copy of the attempt's
// pre-published request (§15.2) and records a redacted diff. It never returns
// bytes to the caller: the live request stays whatever published/passthrough
// produced, shadow errors never fail the attempt, and no upstream call is made.
func (h *Handler) shadowRequest(view *transform.RequestView, cand *router.Candidate, endpointID int64,
	header http.Header, body []byte, keys []string, sensitiveInput bool) {
	if h.transforms == nil || endpointID == 0 {
		return
	}
	c, verID, err := view.ShadowCompiled(cand.Route.ID, endpointID)
	if err != nil {
		h.log.Warn("加载 shadow transform 失败", "err", err, "route", cand.Route.ID)
		return
	}
	if c == nil {
		return
	}
	if encoding := normalizeContentEncoding(header.Get("Content-Encoding")); encoding != "" &&
		(c.HasRequestBodyRules() || c.AllowsRequestReencoding()) {
		var decodeErr error
		if c.AllowsRequestReencoding() {
			body, decodeErr = decodeTransformBody(encoding, body, transform.MaxBodyBuffer)
		}
		if !c.AllowsRequestReencoding() || decodeErr != nil {
			h.transforms.RecordExecution(transform.ExecutionRecord{
				RouteID: cand.Route.ID, EndpointID: endpointID, VersionID: verID,
				Mode: "shadow", Phase: "request", OK: false,
				Error: "压缩请求的 shadow 正文转换不可用", DiffSummary: "omitted: incomplete",
			})
			return
		}
		header = header.Clone()
		header.Del("Content-Encoding")
	}
	var secrets transform.SecretMap
	if key := cand.Upstream.APIKey; key != "" && !model.APIKeyTooShortForOutbound(key) {
		secrets = transform.SecretMap{"upstream_api_key": []byte(key)}
	}
	summary := "request diff=omitted(secret_taint) err=not_evaluated"
	if !sensitiveInput && !containsAttemptSecret(body, keys) {
		summary = c.ShadowDiffSecrets("request", transform.RequestInput{Header: header, Body: body}, transform.ResponseInput{}, secrets)
	}
	inputHash := safeAttemptBodyHash(body, keys)
	if sensitiveInput || containsAttemptSecret(body, keys) || strings.Contains(summary, "secret_taint") {
		inputHash = ""
	}
	h.transforms.RecordExecution(transform.ExecutionRecord{
		RouteID: cand.Route.ID, EndpointID: endpointID, VersionID: verID,
		Mode: "shadow", Phase: "request",
		OK:          strings.HasSuffix(summary, " err="),
		DiffSummary: sample.RedactDiagnosticText(summary, keys),
		InputHash:   inputHash,
	})
}

// responseShadow runs the bound shadow version on a side copy of the response
// the client receives (§15.2). It is attached to the Forwarder's RespTee, so it
// only sees bytes after published/passthrough already wrote them; it never
// writes to the client, never fails the commit, and opens no upstream call.
// Non-stream bodies are copied up to MaxBodyBuffer (the published buffer cap);
// SSE is framed on the copy and each event is shadowed after its live flush.
type responseShadow struct {
	h     *Handler
	la    *liveAttempt
	w     http.ResponseWriter
	c     *transform.Compiled
	verID int64
	sse   bool

	body []byte

	started bool
	stopped bool
	scanner transform.SSEScanner
	acc     *transform.SSEShadow
}

// attachResponseShadow returns nil (no extra work) when no shadow is bound.
func (h *Handler) attachResponseShadow(w http.ResponseWriter, la *liveAttempt) *responseShadow {
	if h.transforms == nil || la == nil || la.endpointID == 0 || la.at == nil ||
		la.at.f == nil || la.at.resp == nil {
		return nil
	}
	c, verID, err := la.transforms.ShadowCompiled(la.cand.Route.ID, la.endpointID)
	if err != nil {
		h.log.Warn("加载 shadow transform 失败", "err", err, "route", la.cand.Route.ID)
		return nil
	}
	if c == nil {
		return nil
	}
	s := &responseShadow{h: h, la: la, w: w, c: c, verID: verID,
		sse: transform.IsSSEContentType(la.at.resp.Header.Get("Content-Type"))}
	if s.sse {
		s.acc = c.NewSSEShadow().WithSensitiveValues(la.keys)
	}
	if f := la.at.f; f.RespTee != nil {
		f.RespTee = io.MultiWriter(f.RespTee, s)
	} else {
		f.RespTee = s
	}
	return s
}

// Write receives a copy of bytes already written to the client. It never
// returns an error: a failing tee would cut the other RespTee writers short.
func (s *responseShadow) Write(p []byte) (int, error) {
	if !s.sse {
		if room := transform.MaxBodyBuffer + 1 - len(s.body); room > 0 {
			if room > len(p) {
				room = len(p)
			}
			s.body = append(s.body, p[:room]...)
		}
		return len(p), nil
	}
	if !s.started {
		s.started = true
		// Live bytes still carry Content-Encoding: the copy cannot be framed.
		if enc := normalizeContentEncoding(s.w.Header().Get("Content-Encoding")); enc != "" {
			s.acc.Fail(fmt.Errorf("cannot shadow SSE with Content-Encoding %q", enc))
			s.stopped = true
		}
	}
	if s.stopped {
		return len(p), nil
	}
	events, err := s.scanner.Feed(p)
	for _, ev := range events {
		s.acc.Event(ev)
	}
	var limitErr *transform.SSELimitError
	if errors.As(err, &limitErr) {
		s.acc.Fail(err)
		s.stopped = true
	}
	return len(p), nil
}

// finish records the shadow diff once the live commit is done. Nothing is
// recorded when the client never received a response (pre-Commit fail_closed).
func (s *responseShadow) finish(res *Result) {
	if s == nil || res == nil || !res.HeadersSent {
		return
	}
	header := s.w.Header().Clone()
	if !s.sse {
		body := s.body
		if encoding := normalizeContentEncoding(header.Get("Content-Encoding")); encoding != "" && !responseRulesTouchBody(s.c) {
			s.record("response", "response diff=omitted(incomplete) err=not_evaluated", false, nil)
			return
		}
		if enc := normalizeContentEncoding(header.Get("Content-Encoding")); enc != "" &&
			responseRulesTouchBody(s.c) && len(body) <= transform.MaxBodyBuffer {
			var err error
			if !contentEncodingDecodable(enc) {
				err = fmt.Errorf("cannot shadow response with Content-Encoding %q", enc)
			} else if body, err = decodeTransformBody(enc, body, transform.MaxBodyBuffer); err == nil {
				header.Del("Content-Encoding")
				header.Del("Content-MD5")
				header.Del("ETag")
			}
			if err != nil {
				s.record("response", "response diff=omitted(incomplete) err=decode_unavailable", false, nil)
				return
			}
		}
		if containsAttemptSecret(body, s.la.keys) {
			s.record("response", "response diff=omitted(secret_taint) err=", true, body)
			return
		}
		summary := s.c.ShadowDiffSecrets("response", transform.RequestInput{},
			transform.ResponseInput{Status: res.Status, Header: header, Body: body}, nil)
		s.record("response", summary, strings.HasSuffix(summary, " err="), body)
		return
	}
	summary := s.c.ShadowDiffSecrets("response", transform.RequestInput{},
		transform.ResponseInput{Status: res.Status, Header: header}, nil)
	s.record("response", summary, strings.HasSuffix(summary, " err="), nil)
	if !s.stopped {
		if ev, ok := s.scanner.Flush(); ok {
			s.acc.Event(ev)
		}
	}
	rec := transform.ExecutionRecord{
		RouteID: s.la.cand.Route.ID, EndpointID: s.la.endpointID, VersionID: s.verID,
		Mode: "shadow", Phase: "sse",
		OK:          s.acc.Err() == "",
		DiffSummary: sample.RedactDiagnosticText(s.acc.Summary(), s.la.keys),
		InputHash:   s.acc.InputHash(),
	}
	if s.stopped {
		rec.InputHash = ""
		rec.DiffSummary = "sse diff=omitted(incomplete) err=decode_unavailable"
	}
	s.h.transforms.RecordExecution(rec)
}

func (s *responseShadow) record(phase, summary string, ok bool, input []byte) {
	inputHash := safeAttemptBodyHash(input, s.la.keys)
	if strings.Contains(summary, "omitted(") {
		inputHash = ""
	}
	if containsAttemptSecret(input, s.la.keys) || strings.Contains(summary, "secret_taint") {
		summary = phase + " diff=omitted(secret_taint) err="
		if !ok {
			summary += "transform_failed"
		}
		inputHash = ""
	}
	s.h.transforms.RecordExecution(transform.ExecutionRecord{
		RouteID: s.la.cand.Route.ID, EndpointID: s.la.endpointID, VersionID: s.verID,
		Mode: "shadow", Phase: phase,
		OK:          ok,
		DiffSummary: sample.RedactDiagnosticText(summary, s.la.keys),
		InputHash:   inputHash,
	})
}
