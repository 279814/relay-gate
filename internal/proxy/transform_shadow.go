package proxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/transform"
)

// shadowRequest runs the bound shadow version on a side copy of the attempt's
// pre-published request (§15.2) and records a redacted diff. It never returns
// bytes to the caller: the live request stays whatever published/passthrough
// produced, shadow errors never fail the attempt, and no upstream call is made.
func (h *Handler) shadowRequest(cand *router.Candidate, endpointID int64,
	header http.Header, body []byte) {
	if h.transforms == nil || endpointID == 0 {
		return
	}
	c, verID, err := h.transforms.ShadowCompiled(cand.Route.ID, endpointID)
	if err != nil {
		h.log.Warn("加载 shadow transform 失败", "err", err, "route", cand.Route.ID)
		return
	}
	if c == nil {
		return
	}
	var secrets transform.SecretMap
	if key := cand.Upstream.APIKey; key != "" && !model.APIKeyTooShortForOutbound(key) {
		secrets = transform.SecretMap{"upstream_api_key": []byte(key)}
	}
	summary := c.ShadowDiffSecrets("request",
		transform.RequestInput{Header: header, Body: body}, transform.ResponseInput{}, secrets)
	h.transforms.RecordExecution(transform.ExecutionRecord{
		RouteID: cand.Route.ID, EndpointID: endpointID, VersionID: verID,
		Mode: "shadow", Phase: "request",
		OK:          strings.HasSuffix(summary, " err="),
		DiffSummary: summary,
		InputHash:   transform.HashBytes(body),
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
	c, verID, err := h.transforms.ShadowCompiled(la.cand.Route.ID, la.endpointID)
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
		s.acc = c.NewSSEShadow()
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
				s.record("response", "response err="+err.Error(), false, s.body)
				return
			}
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
		DiffSummary: s.acc.Summary(),
		InputHash:   s.acc.InputHash(),
	}
	s.h.transforms.RecordExecution(rec)
}

func (s *responseShadow) record(phase, summary string, ok bool, input []byte) {
	s.h.transforms.RecordExecution(transform.ExecutionRecord{
		RouteID: s.la.cand.Route.ID, EndpointID: s.la.endpointID, VersionID: s.verID,
		Mode: "shadow", Phase: phase,
		OK:          ok,
		DiffSummary: summary,
		InputHash:   transform.HashBytes(input),
	})
}
