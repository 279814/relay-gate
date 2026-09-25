package proxy

import (
	"bytes"
	"fmt"
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

	// §15: non-stream body transform requires a complete read within MaxBodyBuffer.
	// Over-limit follows the pre-Commit fail policy — never commit a truncated
	// prefix as a successful transformed body.
	if len(body) > transform.MaxBodyBuffer {
		return at.commitBodyOverLimit(w, compiled, record, f, body)
	}

	policy := compiled.Version.ResFailPolicy
	if policy == "" {
		policy = transform.FailOpen
	}
	decodedFromEncoding := false
	enc := normalizeContentEncoding(at.resp.Header.Get("Content-Encoding"))
	if responseRulesTouchBody(compiled) && enc != "" {
		if !contentEncodingDecodable(enc) {
			err := fmt.Errorf("cannot transform response with Content-Encoding %q", enc)
			if record != nil {
				record(transform.ExecutionRecord{
					Phase: "response", OK: false, Error: err.Error(), FailPolicyUsed: policy,
					InputHash: transform.HashBytes(body),
				})
			}
			if policy == transform.FailClosed {
				res.Err = err
				if res.DoneAt.IsZero() {
					res.DoneAt = time.Now()
				}
				return res
			}
			// fail_open: refuse body transform; pass original encoded bytes + encoding.
			return at.commitEncodedPassthrough(w, f, body)
		}
		decoded, derr := decodeTransformBody(enc, body, transform.MaxBodyBuffer)
		if derr != nil {
			if record != nil {
				record(transform.ExecutionRecord{
					Phase: "response", OK: false, Error: derr.Error(), FailPolicyUsed: policy,
					InputHash: transform.HashBytes(body),
				})
			}
			if policy == transform.FailClosed {
				res.Err = derr
				if res.DoneAt.IsZero() {
					res.DoneAt = time.Now()
				}
				return res
			}
			return at.commitEncodedPassthrough(w, f, body)
		}
		body = decoded
		decodedFromEncoding = true
	}

	inHdr := at.resp.Header.Clone()
	if decodedFromEncoding {
		// Decoded bytes are no longer encoded; drop wire-body validators too.
		inHdr.Del("Content-Encoding")
		inHdr.Del("Content-MD5")
		inHdr.Del("ETag")
	}
	in := transform.ResponseInput{
		Status: at.resp.StatusCode,
		Header: inHdr,
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
	FinalizeClientResponseHeaders(dst, f.RedactSecrets)
	// Protect layer: length from final body, not upstream.
	dst.Del("Content-Length")
	// Body transform or decode-before-transform: upstream Content-Encoding /
	// Content-MD5 / ETag describe the wire body, not what we are writing.
	if decodedFromEncoding || !bytes.Equal(out.Body, body) {
		dst.Del("Content-Encoding")
		dst.Del("Content-MD5")
		dst.Del("ETag")
	}
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
		res.stampFirstSemantic(f)
	}
	now := time.Now()
	if n > 0 && res.FirstByteAt.IsZero() {
		res.FirstByteAt = now
	}
	if werr != nil && res.Err == nil {
		res.Err = werr
	}
	res.DoneAt = now
	return res
}

// commitBodyOverLimit handles a non-stream upstream body larger than MaxBodyBuffer.
// §15 / §15.7: over-limit follows the pre-Commit fail policy. fail_closed returns
// before any client byte; fail_open submits the original status/headers/full body
// (buffered prefix + remaining upstream bytes) without applying transform rules.
func (at *Attempt) commitBodyOverLimit(w http.ResponseWriter, compiled *transform.Compiled,
	record func(transform.ExecutionRecord), f *Forwarder, prefix []byte) *Result {

	res := at.res
	policy := compiled.Version.ResFailPolicy
	if policy == "" {
		policy = transform.FailOpen
	}
	err := fmt.Errorf("response body exceeds %d byte buffer", transform.MaxBodyBuffer)
	if record != nil {
		record(transform.ExecutionRecord{
			Phase: "response", OK: false, Error: err.Error(), FailPolicyUsed: policy,
			InputHash: transform.HashBytes(nil),
		})
	}
	if policy == transform.FailClosed {
		res.Err = err
		if res.DoneAt.IsZero() {
			res.DoneAt = time.Now()
		}
		return res
	}

	// fail_open: original status/headers/body, no transform (§15.7).
	dst := w.Header()
	for k, vs := range at.resp.Header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	FinalizeClientResponseHeaders(dst, f.RedactSecrets)
	w.WriteHeader(at.resp.StatusCode)
	res.HeadersSent = true
	res.Status = at.resp.StatusCode
	res.RespHeaders = at.resp.Header.Clone()

	// prefix already includes peeked bytes from readResponseBody; do not replay peeked.
	src := io.MultiReader(bytes.NewReader(prefix), at.resp.Body)
	n, werr := f.streamBody(at.ctx, at.clientCtx, w, src, at.resp.Body, res)
	res.BytesWritten = n
	res.DoneAt = time.Now()
	if werr != nil && res.Err == nil {
		res.Err = werr
	}
	return res
}

// commitEncodedPassthrough writes the original encoded body and upstream headers
// without body transform. Used when Content-Encoding cannot be decoded safely
// under fail_open (client keeps a consistent encoding + unmodified bytes).
func (at *Attempt) commitEncodedPassthrough(w http.ResponseWriter, f *Forwarder, body []byte) *Result {
	res := at.res
	dst := w.Header()
	for k, vs := range at.resp.Header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	FinalizeClientResponseHeaders(dst, f.RedactSecrets)
	w.WriteHeader(at.resp.StatusCode)
	res.HeadersSent = true
	res.Status = at.resp.StatusCode
	res.RespHeaders = at.resp.Header.Clone()

	n, werr := w.Write(body)
	res.BytesWritten = int64(n)
	if f.RespTee != nil && n > 0 {
		_, _ = f.RespTee.Write(body[:n])
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	now := time.Now()
	if n > 0 && res.FirstByteAt.IsZero() {
		res.FirstByteAt = now
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
	policy := compiled.Version.ResFailPolicy
	if policy == "" {
		policy = transform.FailOpen
	}

	var src io.Reader = at.resp.Body
	if len(at.peeked) > 0 {
		src = io.MultiReader(bytes.NewReader(at.peeked), at.resp.Body)
	}

	enc := normalizeContentEncoding(at.resp.Header.Get("Content-Encoding"))
	decodedFromEncoding := false
	if enc != "" {
		if !responseRulesTouchSSE(compiled) {
			// Header/status-only: do not frame or re-encode; keep compressed bytes + CE.
			return at.commitSSEEncodedPassthrough(w, compiled, record, src)
		}
		if !contentEncodingDecodable(enc) {
			err := fmt.Errorf("cannot transform SSE with Content-Encoding %q", enc)
			if record != nil {
				record(transform.ExecutionRecord{
					Phase: "sse", OK: false, Error: err.Error(), FailPolicyUsed: policy,
				})
			}
			if policy == transform.FailClosed {
				res.Err = err
				return res
			}
			return at.commitSSEEncodedPassthrough(w, compiled, record, src)
		}
		dec, derr := newContentEncodingStream(enc, src)
		if derr != nil {
			if record != nil {
				record(transform.ExecutionRecord{
					Phase: "sse", OK: false, Error: derr.Error(), FailPolicyUsed: policy,
				})
			}
			if policy == transform.FailClosed {
				res.Err = derr
				return res
			}
			// Reconstruct src — peek was already consumed into MultiReader; for
			// fail_open after NewReader failure, gzip/zlib may have read a few
			// header bytes. Refuse partial decode: stream nothing and keep CE
			// only if we can rebuild. Safest fail_open: passthrough via original
			// body is unsafe after a failed decoder peek. Fall closed on stream
			// setup failure even under fail_open when peeked bytes may be lost.
			res.Err = derr
			return res
		}
		defer dec.Close()
		src = dec
		decodedFromEncoding = true
	}

	// Header/status rules before any client byte; body left empty so
	// replace_bytes / json pointer are no-ops on the SSE wire.
	hdrIn := transform.ResponseInput{
		Status: at.resp.StatusCode,
		Header: at.resp.Header.Clone(),
		Body:   nil,
	}
	if decodedFromEncoding {
		hdrIn.Header.Del("Content-Encoding")
		hdrIn.Header.Del("Content-MD5")
		hdrIn.Header.Del("ETag")
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
	FinalizeClientResponseHeaders(dst, f.RedactSecrets)
	dst.Del("Content-Length")
	// ApplySSEEvent always re-encodes event.Raw via encodeSSE, so the wire
	// body is not the upstream byte stream. A leftover Content-Encoding
	// (gzip/deflate/br) would ask the client to decode transformed frames.
	// Content-MD5 / ETag likewise describe the upstream body.
	dst.Del("Content-Encoding")
	dst.Del("Content-MD5")
	dst.Del("ETag")
	w.WriteHeader(hdrOut.Status)
	res.HeadersSent = true
	res.Status = hdrOut.Status
	res.RespHeaders = hdrOut.Header.Clone()

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
				res.stampFirstSemantic(f)
			}
		}
		if res.FirstByteAt.IsZero() && wn > 0 {
			res.FirstByteAt = time.Now()
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

// commitSSEEncodedPassthrough applies header/status rules only and streams the
// original encoded body with Content-Encoding kept. Used when SSE rewrite would
// otherwise parse compressed bytes, or when decoding is unavailable under fail_open.
func (at *Attempt) commitSSEEncodedPassthrough(w http.ResponseWriter, compiled *transform.Compiled,
	record func(transform.ExecutionRecord), src io.Reader) *Result {

	res, f := at.res, at.f
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
	FinalizeClientResponseHeaders(dst, f.RedactSecrets)
	// Keep Content-Encoding / Content-MD5 / ETag: body bytes are unmodified wire.
	w.WriteHeader(hdrOut.Status)
	res.HeadersSent = true
	res.Status = hdrOut.Status
	res.RespHeaders = hdrOut.Header.Clone()

	n, werr := f.streamBody(at.ctx, at.clientCtx, w, src, at.resp.Body, res)
	res.BytesWritten = n
	res.DoneAt = time.Now()
	if werr != nil && res.Err == nil {
		res.Err = werr
	}
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
