package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/transform"
)

type wireRoundTripper func(*http.Request) (*http.Response, error)

func (fn wireRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

type pendingReadFixture struct {
	started, exited, closed chan struct{}
	once                    sync.Once
	closeCount              atomic.Int32
}

func (body *pendingReadFixture) Read(p []byte) (int, error) {
	close(body.started)
	defer close(body.exited)
	<-body.closed
	return 0, io.ErrClosedPipe
}
func (body *pendingReadFixture) Close() error {
	body.closeCount.Add(1)
	body.once.Do(func() { close(body.closed) })
	return nil
}

func TestPeekPendingReadCancellationAndDiscardCloseExactlyOnce(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "discard", true: "cancel-commit"}[commit], func(t *testing.T) {
			body := &pendingReadFixture{started: make(chan struct{}), exited: make(chan struct{}), closed: make(chan struct{})}
			to := RealTimeouts(model.DefaultSettings())
			to.PeekWait = time.Millisecond
			to.FirstSemantic = time.Second
			to.Total = time.Second
			f := &Forwarder{Transport: wireRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: body}, nil
			}), Timeouts: to, Protocol: model.ProtoAnthropic}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			at := f.Send(ctx, "POST", "http://fixture.invalid", nil, nil)
			_ = at.Peek()
			if commit {
				cancel()
				res := at.Commit(httptest.NewRecorder())
				if !errors.Is(res.Err, ErrCanceled) {
					t.Fatalf("cancelled pending read: %v", res.Err)
				}
			} else {
				at.Discard()
				at.Discard()
			}
			select {
			case <-body.exited:
			case <-time.After(time.Second):
				t.Fatal("the single pending read worker did not exit")
			}
			if body.closeCount.Load() != 1 {
				t.Fatalf("transport Close called %d times", body.closeCount.Load())
			}
		})
	}
}

func TestActualBodyTimeoutInsidePeekWindowRemains504WithoutReplay(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer up.Close()
	client := &http.Client{Timeout: 40 * time.Millisecond}
	f := testForwarder(t, Timeouts{FirstSemantic: time.Second, PeekWait: time.Second, CommitOnPeekTimeout: true, Total: 2 * time.Second})
	f.Transport = wireRoundTripper(client.Do)
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, nil)
	_ = at.Peek()
	at.Discard()
	if !at.Failed() || at.CanCommit() {
		t.Fatalf("known body timeout remained committable: %v", at.Result().Err)
	}
	rec := httptest.NewRecorder()
	(&Handler{}).writeForwardError(rec, at.Result().Err, model.ProtoAnthropic, &router.Candidate{Upstream: &model.Upstream{Name: "fixture"}}, nil)
	if rec.Code != 504 || hits.Load() != 1 {
		t.Fatalf("timeout status=%d requests=%d error=%v", rec.Code, hits.Load(), at.Result().Err)
	}
}

func TestPeekShortWindowCommitsHeadersWithoutClosingPendingRead(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer up.Close()
	to := RealTimeouts(model.DefaultSettings())
	to.FirstSemantic, to.PeekWait, to.Total = 300*time.Millisecond, 25*time.Millisecond, time.Second
	f := testForwarder(t, to)
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, nil)
	_ = at.Peek()
	close(release)
	if at.Failed() || !at.CanCommit() {
		at.Discard()
		t.Fatalf("an undecided short peek window must keep the live body: %v", at.Result().Err)
	}
	rec := httptest.NewRecorder()
	res := at.Commit(rec)
	if res.Err != nil || !strings.Contains(rec.Body.String(), `"text":"ok"`) {
		t.Fatalf("pending first read was lost: err=%v body=%q", res.Err, rec.Body.String())
	}
}

func TestPeekWindowActuallyFlushesHeadersBeforeFirstBodyByte(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"late"}]}`)
		case <-r.Context().Done():
		}
	}))
	defer up.Close()
	to := RealTimeouts(model.DefaultSettings())
	to.PeekWait = 20 * time.Millisecond
	to.FirstSemantic = time.Second
	to.Total = 2 * time.Second
	f := testForwarder(t, to)
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at := f.Send(r.Context(), "POST", up.URL, http.Header{}, nil)
		_ = at.Peek()
		if at.CanCommit() {
			at.Commit(w)
		} else {
			at.Discard()
			w.WriteHeader(504)
		}
	}))
	defer gate.Close()
	got := make(chan *http.Response, 1)
	failed := make(chan error, 1)
	go func() {
		r, err := http.Get(gate.URL)
		if err != nil {
			failed <- err
		} else {
			got <- r
		}
	}()
	var response *http.Response
	select {
	case response = <-got:
	case err := <-failed:
		close(release)
		t.Fatal(err)
	case <-time.After(300 * time.Millisecond):
		close(release)
		t.Fatal("short peek expiry did not flush headers before body arrived")
	}
	close(release)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || !strings.Contains(string(body), "late") {
		t.Fatalf("status=%d body=%q err=%v", response.StatusCode, body, err)
	}
}

func TestPeekWindowWithResponseTransformsFlushesDecidableHeaders(t *testing.T) {
	for _, mode := range []string{"json-header", "sse-header", "sse-rewrite", "gzip-header", "gzip-rewrite", "br-rewrite", "gzip-split-header"} {
		t.Run(mode, func(t *testing.T) {
			ct, body := "application/json", []byte(`{"content":[{"type":"text","text":"late"}]}`)
			if mode != "json-header" {
				ct = "text/event-stream"
				body = []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"late\"}}\n\n")
			}
			if strings.HasPrefix(mode, "gzip-") {
				body = gzipBody(t, body)
			}
			if mode == "br-rewrite" {
				body = brotliBody(body)
			}
			release := make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ct)
				if strings.HasPrefix(mode, "gzip-") {
					w.Header().Set("Content-Encoding", "gzip")
				}
				if mode == "br-rewrite" {
					w.Header().Set("Content-Encoding", "br")
				}
				remaining := body
				if mode == "gzip-split-header" {
					_, _ = w.Write(body[:1])
					remaining = body[1:]
				}
				w.(http.Flusher).Flush()
				select {
				case <-release:
					_, _ = w.Write(remaining)
				case <-r.Context().Done():
				}
			}))
			defer up.Close()
			rules := []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Transformed", Value: "1"}}
			if strings.HasSuffix(mode, "rewrite") || mode == "gzip-split-header" {
				rules = append(rules, transform.Rule{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: "late", To: "late-rewritten"})
			}
			compiled, err := transform.Compile(transform.Version{Rules: rules})
			if err != nil {
				t.Fatal(err)
			}
			to := RealTimeouts(model.DefaultSettings())
			to.PeekWait = 20 * time.Millisecond
			to.FirstSemantic = time.Second
			to.Total = 2 * time.Second
			f := testForwarder(t, to)
			gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				at := f.Send(r.Context(), "POST", up.URL, http.Header{"Accept-Encoding": {"identity"}}, nil)
				_ = at.Peek()
				at.CommitTransformed(w, compiled, nil)
			}))
			defer gate.Close()
			got := make(chan *http.Response, 1)
			failed := make(chan error, 1)
			go func() {
				req, _ := http.NewRequest("GET", gate.URL, nil)
				req.Header.Set("Accept-Encoding", "identity")
				res, err := http.DefaultClient.Do(req)
				if err != nil {
					failed <- err
				} else {
					got <- res
				}
			}()
			var response *http.Response
			select {
			case response = <-got:
			case err := <-failed:
				close(release)
				t.Fatal(err)
			case <-time.After(300 * time.Millisecond):
				close(release)
				t.Fatal("response transform delayed decidable headers past the peek window")
			}
			close(release)
			defer response.Body.Close()
			output, err := io.ReadAll(response.Body)
			if err != nil || response.Header.Get("X-Transformed") != "1" {
				t.Fatalf("headers=%v err=%v", response.Header, err)
			}
			if mode == "gzip-header" {
				if string(output) != string(body) {
					t.Fatal("header-only transform changed compressed wire")
				}
			} else if !strings.Contains(string(output), "late") {
				t.Fatalf("late body lost: %q", output)
			}
		})
	}
}

func TestTransformOutputCannotManufactureForwardSemanticEvidence(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "json", true: "sse"}[stream], func(t *testing.T) {
			body, ct := `{"content":[]}`, "application/json"
			rules := []transform.Rule{{Kind: transform.KindReplaceBytes, From: body, To: `{"content":[{"type":"text","text":"injected"}]}`}}
			if stream {
				body, ct = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"\"}}\n\n", "text/event-stream"
				rules = []transform.Rule{{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: `"text":""`, To: `"text":"injected"`}}
			}
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ct)
				_, _ = w.Write([]byte(body))
			}))
			defer up.Close()
			reg := transform.NewRegistry(4)
			set, err := reg.CreateSet("wire-only")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailClosed, ""); err != nil {
				t.Fatal(err)
			}
			_, _, err = reg.PublishSnapshot(set.ID, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			compiled, _, err := reg.PublishedCompiled(1, 1)
			if err != nil {
				t.Fatal(err)
			}
			f := testForwarder(t, fastTimeouts())
			at := f.Send(context.Background(), "POST", up.URL, http.Header{}, nil)
			rec := httptest.NewRecorder()
			res := at.CommitTransformed(rec, compiled, nil)
			if res.Err != nil {
				t.Fatal(res.Err)
			}
			if !strings.Contains(rec.Body.String(), "injected") {
				t.Fatalf("fixture did not inject semantic text: %q", rec.Body.String())
			}
			if res.SemanticSeen || !res.FirstSemanticAt.IsZero() {
				t.Fatalf("transform output forged raw semantic evidence: %+v", res)
			}
		})
	}
}

func TestForwardRawKeepaliveAfterSemanticResetsIdle(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n"))
		w.(http.Flusher).Flush()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		until := time.NewTimer(200 * time.Millisecond)
		defer until.Stop()
		for {
			select {
			case <-ticker.C:
				_, _ = w.Write([]byte(": heartbeat\n\n"))
				w.(http.Flusher).Flush()
			case <-until.C:
				return
			case <-r.Context().Done():
				return
			}
		}
	}))
	defer up.Close()
	f := testForwarder(t, Timeouts{FirstSemantic: time.Second, Idle: 60 * time.Millisecond, Total: time.Second})
	res := f.Forward(context.Background(), httptest.NewRecorder(), "POST", up.URL, http.Header{}, nil)
	if res.Err != nil || !res.SemanticSeen {
		t.Fatalf("original keepalives after semantic must keep the stream active: %v", res.Err)
	}
}

func TestTransformOutputCannotSatisfyRawFirstSemanticTimeout(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		end := time.NewTimer(250 * time.Millisecond)
		defer end.Stop()
		for {
			select {
			case <-ticker.C:
				_, _ = io.WriteString(w, "event: ping\ndata: {\"type\":\"ping\"}\n\n")
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			case <-end.C:
				return
			}
		}
	}))
	defer up.Close()
	compiled, err := transform.Compile(transform.Version{Rules: []transform.Rule{{Kind: transform.KindSSEMatch, Match: "ping", From: `{"type":"ping"}`, To: `{"type":"content_block_delta","delta":{"type":"text_delta","text":"injected"}}`}}})
	if err != nil {
		t.Fatal(err)
	}
	f := testForwarder(t, Timeouts{FirstSemantic: 80 * time.Millisecond, Idle: time.Second, Total: time.Second})
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, nil)
	if at.Failed() {
		at.Discard()
		t.Fatal(at.Result().Err)
	}
	rec := httptest.NewRecorder()
	res := at.CommitTransformed(rec, compiled, nil)
	if !strings.Contains(rec.Body.String(), "injected") {
		t.Fatalf("fixture did not rewrite ping: %q", rec.Body.String())
	}
	if !errors.Is(res.Err, ErrFirstTokenTimeout) || res.SemanticSeen {
		t.Fatalf("transformed heartbeat must not satisfy the original semantic gate: %+v", res)
	}
}
