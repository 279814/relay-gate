package proxy

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/transform"
)

// commitLive writes the attempt to the client, optionally applying a published
// response / SSE transform. Unbound (compiled == nil) stays pure passthrough.
func (h *Handler) commitLive(w http.ResponseWriter, la *liveAttempt) *Result {
	if la.compiled == nil {
		return la.at.Commit(w)
	}
	return la.at.CommitTransformed(w, la.compiled, func(rec transform.ExecutionRecord) {
		if h.transforms == nil {
			return
		}
		rec.RouteID = la.cand.Route.ID
		rec.EndpointID = la.endpointID
		rec.VersionID = la.verID
		rec.Mode = "published"
		h.transforms.RecordExecution(rec)
	})
}

// CommitTransformed applies published response rules before / while writing
// to the client (§15). fail_closed before any client byte returns HeadersSent
// false so the caller can emit a local error; after Commit, fail_closed only
// terminates the stream.
func (at *Attempt) CommitTransformed(w http.ResponseWriter, compiled *transform.Compiled,
	record func(transform.ExecutionRecord)) *Result {

	if at.done {
		return at.res
	}
	at.done = true
	defer at.cancel()
	defer at.resp.Body.Close()

	ct := at.resp.Header.Get("Content-Type")
	if transform.IsSSEContentType(ct) {
		return at.commitSSE(w, compiled, record)
	}
	return at.commitBuffered(w, compiled, record, at.f)
}

func (at *Attempt) commitBuffered(w http.ResponseWriter, compiled *transform.Compiled,
	record func(transform.ExecutionRecord), f *Forwarder) *Result {

	res := at.res
	body, err := at.readResponseBody(transform.MaxBodyBuffer)
	if err != nil {
		res.Err = err
		if res.DoneAt.IsZero() {
			res.DoneAt = time.Now()
		}
		policy := compiled.Version.ResFailPolicy
		if policy == "" {
			policy = transform.FailOpen
		}
		if policy == transform.FailClosed {
			if record != nil {
				record(transform.ExecutionRecord{
					Phase: "response", OK: false, Error: err.Error(), FailPolicyUsed: policy,
					InputHash: transform.HashBytes(nil),
				})
			}
			return res
		}
		// fail_open on transport read error: pass empty body into ApplyResponse
		// so header rules still run; body stays empty.
		body = nil
	}

	in := transform.ResponseInput{
		Status: at.resp.StatusCode,
		Header: at.resp.Header.Clone(),
		Body:   body,
	}
	out := compiled.ApplyResponse(in)
	if out.Err != nil && out.PolicyUsed == transform.FailClosed {
		res.Err = out.Err
		if record != nil {
			record(transform.ExecutionRecord{
				Phase: "response", OK: false, Error: out.Err.Error(),
				FailPolicyUsed: out.PolicyUsed, HitRules: out.HitRules,
				InputHash: transform.HashBytes(body),
			})
		}
		return res
	}
	if out.Changed || out.Err != nil {
		errText := ""
		if out.Err != nil {
			errText = out.Err.Error()
		}
		if record != nil {
			record(transform.ExecutionRecord{
				Phase: "response", OK: out.Err == nil, Error: errText,
				FailPolicyUsed: out.PolicyUsed, HitRules: out.HitRules,
				InputHash: transform.HashBytes(body), OutputHash: transform.HashBytes(out.Body),
			})
		}
	}

	dst := w.Header()
	for k, vs := range out.Header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	StripHopByHopResponse(dst)
	// Protect layer: length from final body, not upstream.
	dst.Del("Content-Length")
	w.WriteHeader(out.Status)
	res.HeadersSent = true
	res.Status = out.Status
	res.RespHeaders = out.Header.Clone()

	n, werr := w.Write(out.Body)
	res.BytesWritten = int64(n)
	if f.RespTee != nil && n > 0 {
		_, _ = f.RespTee.Write(out.Body[:n])
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	// flush 之后再判语义：body 已完整缓冲在 transform 路径，不额外读上游。
	if res.Status >= 200 && res.Status < 400 &&
		!IsStructuredErrorPayload(out.Body, out.Header.Get("Content-Type")) &&
		HasSemanticEvidence(out.Body, out.Header.Get("Content-Type")) {
		res.SemanticSeen = true
	}
	now := time.Now()
	if n > 0 && res.FirstByteAt.IsZero() {
		res.FirstByteAt = now
		if f.OnFirstByte != nil {
			f.OnFirstByte()
		}
	}
	if werr != nil && res.Err == nil {
		res.Err = werr
	}
	res.DoneAt = now
	return res
}

func (at *Attempt) commitSSE(w http.ResponseWriter, compiled *transform.Compiled,
	record func(transform.ExecutionRecord)) *Result {

	res, f := at.res, at.f
	// Header/status rules before any client byte; body left empty so
	// replace_bytes / json pointer are no-ops on the SSE wire.
	hdrIn := transform.ResponseInput{
		Status: at.resp.StatusCode,
		Header: at.resp.Header.Clone(),
		Body:   nil,
	}
	hdrOut := compiled.ApplyResponse(hdrIn)
	if hdrOut.Err != nil && hdrOut.PolicyUsed == transform.FailClosed {
		res.Err = hdrOut.Err
		if record != nil {
			record(transform.ExecutionRecord{
				Phase: "response", OK: false, Error: hdrOut.Err.Error(),
				FailPolicyUsed: hdrOut.PolicyUsed, HitRules: hdrOut.HitRules,
			})
		}
		return res
	}

	dst := w.Header()
	for k, vs := range hdrOut.Header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	StripHopByHopResponse(dst)
	dst.Del("Content-Length")
	w.WriteHeader(hdrOut.Status)
	res.HeadersSent = true
	res.Status = hdrOut.Status
	res.RespHeaders = hdrOut.Header.Clone()

	var src io.Reader = at.resp.Body
	if len(at.peeked) > 0 {
		src = io.MultiReader(bytes.NewReader(at.peeked), at.resp.Body)
	}

	policy := compiled.Version.ResFailPolicy
	if policy == "" {
		policy = transform.FailOpen
	}
	scanner := &transform.SSEScanner{}
	buf := make([]byte, 32*1024)
	flusher, canFlush := w.(http.Flusher)
	var total int64
	var hitAll []string
	ct := ""
	if res.RespHeaders != nil {
		ct = res.RespHeaders.Get("Content-Type")
	}
	if ct == "" && at.resp != nil {
		ct = at.resp.Header.Get("Content-Type")
	}
	var semSniffer *streamSemanticSniffer
	if res.Status >= 200 && res.Status < 400 {
		semSniffer = newStreamSemanticSniffer(ct)
	}

	writeEv := func(ev transform.SSEEvent) error {
		if len(ev.Raw) == 0 {
			return nil
		}
		wn, werr := w.Write(ev.Raw)
		total += int64(wn)
		if f.RespTee != nil && wn > 0 {
			_, _ = f.RespTee.Write(ev.Raw[:wn])
		}
		if canFlush {
			flusher.Flush()
		}
		if semSniffer != nil && !semSniffer.Seen() && wn > 0 {
			semSniffer.Feed(ev.Raw[:wn], ct)
			if semSniffer.Seen() {
				res.SemanticSeen = true
			}
		}
		if res.FirstByteAt.IsZero() && wn > 0 {
			res.FirstByteAt = time.Now()
			if f.OnFirstByte != nil {
				f.OnFirstByte()
			}
		}
		return werr
	}

	for {
		n, err := src.Read(buf)
		if n > 0 {
			events, ferr := scanner.Feed(buf[:n])
			if ferr != nil {
				res.Err = ferr
				if policy == transform.FailClosed {
					if record != nil {
						record(transform.ExecutionRecord{
							Phase: "sse", OK: false, Error: ferr.Error(), FailPolicyUsed: policy,
						})
					}
					res.BytesWritten = total
					return res
				}
			}
			for _, ev := range events {
				out, hits, _, aerr := compiled.ApplySSEEvent(ev)
				if aerr != nil {
					if policy == transform.FailClosed {
						res.Err = aerr
						if record != nil {
							record(transform.ExecutionRecord{
								Phase: "sse", OK: false, Error: aerr.Error(),
								FailPolicyUsed: policy, HitRules: hits,
							})
						}
						res.BytesWritten = total
						return res
					}
					out = ev // fail_open: original event
				}
				hitAll = append(hitAll, hits...)
				if werr := writeEv(out); werr != nil {
					res.Err = werr
					res.BytesWritten = total
					return res
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			res.Err = err
			res.BytesWritten = total
			return res
		}
	}
	if ev, ok := scanner.Flush(); ok {
		out, hits, _, aerr := compiled.ApplySSEEvent(ev)
		if aerr != nil && policy == transform.FailClosed {
			res.Err = aerr
			if record != nil {
				record(transform.ExecutionRecord{
					Phase: "sse", OK: false, Error: aerr.Error(),
					FailPolicyUsed: policy, HitRules: hits,
				})
			}
			res.BytesWritten = total
			return res
		}
		if aerr == nil {
			hitAll = append(hitAll, hits...)
			_ = writeEv(out)
		} else {
			_ = writeEv(ev)
		}
	}
	if syn, ok := compiled.AppendSyntheticEnd(); ok {
		_ = writeEv(syn)
		hitAll = append(hitAll, "sse_append_end")
	}
	if len(hitAll) > 0 && record != nil {
		record(transform.ExecutionRecord{
			Phase: "sse", OK: true, HitRules: hitAll, FailPolicyUsed: policy,
		})
	}
	res.BytesWritten = total
	res.DoneAt = time.Now()
	return res
}

func (at *Attempt) readResponseBody(limit int) ([]byte, error) {
	var src io.Reader = at.resp.Body
	if len(at.peeked) > 0 {
		src = io.MultiReader(bytes.NewReader(at.peeked), at.resp.Body)
	}
	var buf bytes.Buffer
	// Read limit+1 so ApplyResponse can detect overflow and apply fail policy.
	_, err := io.Copy(&buf, io.LimitReader(src, int64(limit)+1))
	if err != nil && err != io.EOF {
		return buf.Bytes(), err
	}
	return buf.Bytes(), nil
}
