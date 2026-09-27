package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

func shadowRecords(reg *transform.Registry) []transform.ExecutionRecord {
	var out []transform.ExecutionRecord
	for _, rec := range reg.ListExecutions(0) {
		if rec.Mode == "shadow" {
			out = append(out, rec)
		}
	}
	return out
}

func shadowPhase(reg *transform.Registry, phase string) []transform.ExecutionRecord {
	var out []transform.ExecutionRecord
	for _, rec := range shadowRecords(reg) {
		if rec.Phase == phase {
			out = append(out, rec)
		}
	}
	return out
}

// §15.2: a bound shadow version computes its diff on a side copy of the live
// request. The upstream still receives the published bytes, exactly one
// upstream call is made, and the recorded diff carries hashes/hit rules only.
func TestShadowBinding_LiveSideCopyDiffWithoutChangingRequest(t *testing.T) {
	var upstreamCalls atomic.Int32
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	})

	reg := transform.NewRegistry(16)
	set, err := reg.CreateSet("shadow-live")
	if err != nil {
		t.Fatal(err)
	}
	pubRules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: `"max_tokens":1`, To: `"max_tokens":2`},
	}
	if _, err := reg.UpdateDraft(set.ID, pubRules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	// harness Route.ID=100, Endpoint.ID=1
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	shadowRules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: `"max_tokens":1`, To: `"max_tokens":99`},
		{Kind: transform.KindSetHeader, Name: "X-Shadow-Key", SecretRef: "upstream_api_key"},
	}
	if _, err := reg.UpdateDraft(set.ID, shadowRules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	_, shadowVer, err := reg.ShadowSnapshot(set.ID, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	body := `{"model":"claude-opus-5","max_tokens":1}`
	rec := hs.serve(hs.anthropicRequest(body))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if n := upstreamCalls.Load(); n != 1 {
		t.Fatalf("shadow must not send extra upstream requests: calls=%d", n)
	}
	if want := `{"model":"claude-opus-5","max_tokens":2}`; string(hs.gotReq.body) != want {
		t.Fatalf("upstream must get published bytes: got %s want %s", hs.gotReq.body, want)
	}
	if hs.gotReq.headers.Get("X-Shadow-Key") != "" {
		t.Fatal("shadow header leaked into live request")
	}

	recs := shadowPhase(reg, "request")
	if len(recs) != 1 {
		t.Fatalf("want 1 request shadow record, got %d: %+v", len(recs), reg.ListExecutions(0))
	}
	sr := recs[0]
	if sr.VersionID != shadowVer.ID || sr.RouteID != 100 || sr.EndpointID != 1 || sr.Phase != "request" {
		t.Fatalf("shadow record identity: %+v", sr)
	}
	if !sr.OK {
		t.Fatalf("shadow record should be OK: %+v", sr)
	}
	if sr.InputHash != transform.HashBytes([]byte(body)) {
		t.Fatalf("shadow input must be the pre-published request: %s", sr.InputHash)
	}
	shadowOut := transform.HashBytes([]byte(`{"model":"claude-opus-5","max_tokens":99}`))
	if !strings.Contains(sr.DiffSummary, "changed=true") || !strings.Contains(sr.DiffSummary, shadowOut) {
		t.Fatalf("shadow diff missing change/output hash: %s", sr.DiffSummary)
	}
	if !strings.Contains(sr.DiffSummary, "r0:replace_bytes") {
		t.Fatalf("shadow diff missing hit rules: %s", sr.DiffSummary)
	}
	if strings.Contains(sr.DiffSummary, "sk-upstream-secret") || strings.Contains(sr.DiffSummary, "max_tokens") {
		t.Fatalf("shadow diff must not carry secrets or raw body: %s", sr.DiffSummary)
	}
}

// Shadow alone (no published pointer) leaves the passthrough bytes intact.
func TestShadowBinding_ShadowOnlyKeepsPassthrough(t *testing.T) {
	hs := newHarness(t, nil)
	reg := transform.NewRegistry(16)
	set, err := reg.CreateSet("shadow-only")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: `"max_tokens":1`, To: `"max_tokens":99`},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.ShadowSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	body := `{"model":"claude-opus-5","max_tokens":1}`
	rec := hs.serve(hs.anthropicRequest(body))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if string(hs.gotReq.body) != body {
		t.Fatalf("passthrough changed by shadow: %s", hs.gotReq.body)
	}
	if len(shadowPhase(reg, "request")) != 1 {
		t.Fatalf("want 1 request shadow record, got %+v", reg.ListExecutions(0))
	}
}

// §15.2: a bound shadow version also diffs a side copy of the response the
// client receives. The client gets the published bytes, shadow-only header and
// body changes never reach it, and only one upstream call is made.
func TestShadowBinding_ResponseSideCopyKeepsPublishedBytes(t *testing.T) {
	var upstreamCalls atomic.Int32
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"type":"message","text":"live"}`))
	})
	reg := transform.NewRegistry(16)
	set, err := reg.CreateSet("shadow-response")
	if err != nil {
		t.Fatal(err)
	}
	pubRules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: `"text":"live"`, To: `"text":"published"`},
	}
	if _, err := reg.UpdateDraft(set.ID, pubRules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	shadowRules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: `"text":"published"`, To: `"text":"shadowed"`},
		{Kind: transform.KindSetHeader, Name: "X-Shadow-Only", Value: "1"},
	}
	if _, err := reg.UpdateDraft(set.ID, shadowRules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	_, shadowVer, err := reg.ShadowSnapshot(set.ID, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if n := upstreamCalls.Load(); n != 1 {
		t.Fatalf("shadow must not send extra upstream requests: calls=%d", n)
	}
	live := `{"type":"message","text":"published"}`
	if got := rec.Body.String(); got != live {
		t.Fatalf("client must get published bytes: got %s want %s", got, live)
	}
	if rec.Header().Get("X-Shadow-Only") != "" {
		t.Fatal("shadow header leaked into client response")
	}

	recs := shadowPhase(reg, "response")
	if len(recs) != 1 {
		t.Fatalf("want 1 response shadow record, got %d: %+v", len(recs), reg.ListExecutions(0))
	}
	sr := recs[0]
	if sr.VersionID != shadowVer.ID || sr.RouteID != 100 || sr.EndpointID != 1 || !sr.OK {
		t.Fatalf("shadow record identity: %+v", sr)
	}
	if sr.InputHash != transform.HashBytes([]byte(live)) {
		t.Fatalf("shadow input must be the bytes the client received: %s", sr.InputHash)
	}
	shadowOut := transform.HashBytes([]byte(`{"type":"message","text":"shadowed"}`))
	if !strings.Contains(sr.DiffSummary, "changed=true") || !strings.Contains(sr.DiffSummary, shadowOut) {
		t.Fatalf("shadow diff missing change/output hash: %s", sr.DiffSummary)
	}
	if !strings.Contains(sr.DiffSummary, "r0:replace_bytes") || !strings.Contains(sr.DiffSummary, "r1:set_header") {
		t.Fatalf("shadow diff missing hit rules: %s", sr.DiffSummary)
	}
	if strings.Contains(sr.DiffSummary, "published") || strings.Contains(sr.DiffSummary, "shadowed") {
		t.Fatalf("shadow diff must not carry raw body: %s", sr.DiffSummary)
	}
}

// A shadow apply error is recorded and the client still gets the live body.
func TestShadowBinding_ResponseShadowErrorKeepsLiveBody(t *testing.T) {
	upstream := `{"type":"message","text":"live"}`
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(upstream))
	})
	reg := transform.NewRegistry(16)
	set, err := reg.CreateSet("shadow-response-err")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindSetJSONPointer, Name: "/missing", Value: "x"},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.ShadowSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != 200 || rec.Body.String() != upstream {
		t.Fatalf("shadow error must not change live response: status=%d body=%s", rec.Code, rec.Body.String())
	}
	recs := shadowPhase(reg, "response")
	if len(recs) != 1 {
		t.Fatalf("want 1 response shadow record, got %+v", reg.ListExecutions(0))
	}
	if recs[0].OK || strings.HasSuffix(recs[0].DiffSummary, " err=") {
		t.Fatalf("shadow error must be recorded: %+v", recs[0])
	}
}

// SSE: each live event is shadowed on a copy after it is written; the client
// stream carries only published events.
func TestShadowBinding_SSESideCopyPerEvent(t *testing.T) {
	var upstreamCalls atomic.Int32
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\"}\n\n"))
		fl.Flush()
		w.Write([]byte("event: content_block_delta\ndata: {\"delta\":\"hi\"}\n\n"))
		fl.Flush()
	})
	reg := transform.NewRegistry(16)
	set, _ := reg.CreateSet("shadow-sse")
	pubRules := []transform.Rule{
		{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: "hi", To: "hello"},
	}
	if _, err := reg.UpdateDraft(set.ID, pubRules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	shadowRules := []transform.Rule{
		{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: "hello", To: "shadowed"},
		{Kind: transform.KindSetHeader, Name: "X-Shadow-Only", Value: "1"},
	}
	if _, err := reg.UpdateDraft(set.ID, shadowRules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.ShadowSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if n := upstreamCalls.Load(); n != 1 {
		t.Fatalf("shadow must not send extra upstream requests: calls=%d", n)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"delta":"hello"`) || strings.Contains(body, "shadowed") {
		t.Fatalf("client stream must carry published events only: %s", body)
	}
	if rec.Header().Get("X-Shadow-Only") != "" {
		t.Fatal("shadow header leaked into client response")
	}
	recs := shadowPhase(reg, "sse")
	if len(recs) != 1 {
		t.Fatalf("want 1 sse shadow record, got %+v", reg.ListExecutions(0))
	}
	sr := recs[0]
	if !sr.OK || !strings.Contains(sr.DiffSummary, "events=2 changed=1") ||
		!strings.Contains(sr.DiffSummary, "r0:sse_match") {
		t.Fatalf("sse shadow diff: %+v", sr)
	}
	if sr.InputHash != transform.HashBytes([]byte(body)) {
		t.Fatalf("sse shadow input must be the live client stream: %s", sr.InputHash)
	}
	if strings.Contains(sr.DiffSummary, "hello") || strings.Contains(sr.DiffSummary, "shadowed") {
		t.Fatalf("shadow diff must not carry raw events: %s", sr.DiffSummary)
	}
}

type flushTrackingWriter struct {
	*httptest.ResponseRecorder
	written, flushed int
}

func (w *flushTrackingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(p)
	w.written += n
	return n, err
}

func (w *flushTrackingWriter) Flush() {
	w.flushed = w.written
	w.ResponseRecorder.Flush()
}

type flushOrderTee struct {
	w         *flushTrackingWriter
	calls     int
	unflushed int
}

func (p *flushOrderTee) Write(b []byte) (int, error) {
	p.calls++
	if p.w.flushed != p.w.written {
		p.unflushed++
	}
	return len(b), nil
}

// Published SSE: the response tee (where the shadow side copy runs
// ApplySSEEvent) must only see an event after its live flush, so shadow work
// never delays client-visible flush timing.
func TestCommitSSE_RespTeeRunsAfterLiveFlush(t *testing.T) {
	c, err := transform.Compile(transform.Version{Rules: []transform.Rule{
		{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: "hi", To: "hello"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	stream := "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" +
		"event: content_block_delta\ndata: {\"delta\":\"hi\"}\n\n"
	w := &flushTrackingWriter{ResponseRecorder: httptest.NewRecorder()}
	probe := &flushOrderTee{w: w}
	at := &Attempt{
		f: &Forwarder{RespTee: probe},
		resp: &http.Response{StatusCode: 200,
			Header: http.Header{"Content-Type": {"text/event-stream"}},
			Body:   io.NopCloser(strings.NewReader(stream))},
		res:       &Result{},
		cancel:    func() {},
		ctx:       context.Background(),
		clientCtx: context.Background(),
	}
	res := at.CommitTransformed(w, c, nil)
	if res.Err != nil || !res.HeadersSent {
		t.Fatalf("commit: %+v", res)
	}
	if probe.calls != 2 {
		t.Fatalf("tee should see each event once, got %d", probe.calls)
	}
	if probe.unflushed != 0 {
		t.Fatalf("tee saw %d event(s) before their live flush", probe.unflushed)
	}
}

// No shadow pointer: no shadow work and no shadow record.
func TestShadowBinding_UnboundRecordsNothing(t *testing.T) {
	hs := newHarness(t, nil)
	reg := transform.NewRegistry(16)
	hs.h.WithTransforms(reg)
	body := `{"model":"claude-opus-5","max_tokens":1}`
	if rec := hs.serve(hs.anthropicRequest(body)); rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	if n := len(reg.ListExecutions(0)); n != 0 {
		t.Fatalf("unbound must record nothing, got %d", n)
	}
}
