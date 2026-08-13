package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureUpstreamStage string

const (
	fixtureStageDNSBefore fixtureUpstreamStage = "dns_before"
	fixtureStageDNSAfter  fixtureUpstreamStage = "dns_after"
	fixtureStageTCPBefore fixtureUpstreamStage = "tcp_before"
	fixtureStageTCPAfter  fixtureUpstreamStage = "tcp_after"
	fixtureStageTLSBefore fixtureUpstreamStage = "tls_before"
	fixtureStageTLSAfter  fixtureUpstreamStage = "tls_after"
	fixtureStageHeaders   fixtureUpstreamStage = "headers"
	fixtureStageFirstByte fixtureUpstreamStage = "first_byte"
	fixtureStageEvent     fixtureUpstreamStage = "event"
	fixtureStageSemantic  fixtureUpstreamStage = "semantic"
	fixtureStageIdle      fixtureUpstreamStage = "idle"
)

var fixtureUpstreamStages = [...]fixtureUpstreamStage{
	fixtureStageDNSBefore,
	fixtureStageDNSAfter,
	fixtureStageTCPBefore,
	fixtureStageTCPAfter,
	fixtureStageTLSBefore,
	fixtureStageTLSAfter,
	fixtureStageHeaders,
	fixtureStageFirstByte,
	fixtureStageEvent,
	fixtureStageSemantic,
	fixtureStageIdle,
}

type fixtureUpstreamOptions struct {
	AbnormalEOF bool
}

type fixtureStageGate struct {
	reached     chan struct{}
	release     chan struct{}
	reachedOnce sync.Once
	releaseOnce sync.Once
}

type fixtureTestUpstream struct {
	server  *httptest.Server
	client  *http.Client
	gates   map[fixtureUpstreamStage]*fixtureStageGate
	options fixtureUpstreamOptions
}

func newFixtureTestUpstream(t *testing.T, options fixtureUpstreamOptions) *fixtureTestUpstream {
	t.Helper()
	upstream := &fixtureTestUpstream{
		gates:   make(map[fixtureUpstreamStage]*fixtureStageGate, len(fixtureUpstreamStages)),
		options: options,
	}
	for _, stage := range fixtureUpstreamStages {
		upstream.gates[stage] = &fixtureStageGate{
			reached: make(chan struct{}),
			release: make(chan struct{}),
		}
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(upstream.serveHTTP))
	server.EnableHTTP2 = false
	server.StartTLS()
	upstream.server = server

	transport := server.Client().Transport.(*http.Transport).Clone()
	serverAddress := server.Listener.Addr().String()
	tlsConfig := transport.TLSClientConfig.Clone()
	// The certificate is generated for this in-process fixture server. The
	// client is pinned to serverAddress below, so no external host is trusted.
	tlsConfig.InsecureSkipVerify = true //nolint:gosec
	transport.DisableKeepAlives = true
	transport.DialContext = nil
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if err := upstream.wait(ctx, fixtureStageDNSBefore); err != nil {
			return nil, err
		}
		if _, err := net.DefaultResolver.LookupHost(ctx, "localhost"); err != nil {
			return nil, err
		}
		if err := upstream.wait(ctx, fixtureStageDNSAfter); err != nil {
			return nil, err
		}
		if err := upstream.wait(ctx, fixtureStageTCPBefore); err != nil {
			return nil, err
		}
		connection, err := (&net.Dialer{}).DialContext(ctx, network, serverAddress)
		if err != nil {
			return nil, err
		}
		if err := upstream.wait(ctx, fixtureStageTCPAfter); err != nil {
			_ = connection.Close()
			return nil, err
		}
		if err := upstream.wait(ctx, fixtureStageTLSBefore); err != nil {
			_ = connection.Close()
			return nil, err
		}
		tlsConnection := tls.Client(connection, tlsConfig)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			return nil, err
		}
		if err := upstream.wait(ctx, fixtureStageTLSAfter); err != nil {
			_ = tlsConnection.Close()
			return nil, err
		}
		return tlsConnection, nil
	}
	upstream.client = &http.Client{Transport: transport, Timeout: fixtureStageWait}
	return upstream
}

func (u *fixtureTestUpstream) URL() string {
	return u.server.URL
}

func (u *fixtureTestUpstream) Client() *http.Client {
	return u.client
}

func (u *fixtureTestUpstream) WaitReached(t *testing.T, stage fixtureUpstreamStage) {
	t.Helper()
	gate := u.gates[stage]
	select {
	case <-gate.reached:
	case <-time.After(fixtureStageWait):
		t.Fatalf("fixture upstream did not reach %s", stage)
	}
}

func (u *fixtureTestUpstream) Release(stage fixtureUpstreamStage) {
	u.gates[stage].releaseOnce.Do(func() { close(u.gates[stage].release) })
}

func (u *fixtureTestUpstream) ReleaseAll() {
	for _, stage := range fixtureUpstreamStages {
		u.Release(stage)
	}
}

func (u *fixtureTestUpstream) Close() {
	u.ReleaseAll()
	u.client.CloseIdleConnections()
	u.server.Close()
}

func (u *fixtureTestUpstream) wait(ctx context.Context, stage fixtureUpstreamStage) error {
	gate := u.gates[stage]
	gate.reachedOnce.Do(func() { close(gate.reached) })
	select {
	case <-gate.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (u *fixtureTestUpstream) serveHTTP(response http.ResponseWriter, request *http.Request) {
	flusher, ok := response.(http.Flusher)
	if !ok {
		http.Error(response, "streaming unavailable", http.StatusInternalServerError)
		return
	}
	if err := u.wait(request.Context(), fixtureStageHeaders); err != nil {
		return
	}
	response.Header().Set("Content-Type", "text/event-stream")
	if u.options.AbnormalEOF {
		response.Header().Set("Content-Length", "4096")
	}
	response.WriteHeader(http.StatusOK)
	flusher.Flush()

	stagedWrites := []struct {
		stage fixtureUpstreamStage
		data  string
	}{
		{stage: fixtureStageFirstByte, data: ":"},
		{stage: fixtureStageEvent, data: " keepalive\n\n"},
		{stage: fixtureStageSemantic, data: "event: content_block_delta\ndata: {\"text\":\"2\"}\n\n"},
	}
	for _, write := range stagedWrites {
		if err := u.wait(request.Context(), write.stage); err != nil {
			return
		}
		if _, err := io.WriteString(response, write.data); err != nil {
			return
		}
		flusher.Flush()
	}
	_ = u.wait(request.Context(), fixtureStageIdle)
}

func TestFixtureTestUpstreamGatesNetworkAndStreamingStages(t *testing.T) {
	upstream := newFixtureTestUpstream(t, fixtureUpstreamOptions{})
	defer upstream.Close()

	type responseResult struct {
		response *http.Response
		err      error
	}
	responseCh := make(chan responseResult, 1)
	go func() {
		response, err := upstream.Client().Get(upstream.URL())
		responseCh <- responseResult{response: response, err: err}
	}()

	for _, stage := range []fixtureUpstreamStage{
		fixtureStageDNSBefore,
		fixtureStageDNSAfter,
		fixtureStageTCPBefore,
		fixtureStageTCPAfter,
		fixtureStageTLSBefore,
		fixtureStageTLSAfter,
		fixtureStageHeaders,
	} {
		upstream.WaitReached(t, stage)
		assertFixtureResultPending(t, responseCh, stage)
		upstream.Release(stage)
	}

	result := <-responseCh
	if result.err != nil {
		t.Fatalf("GET fixture upstream: %v", result.err)
	}
	defer result.response.Body.Close()

	bodyCh := make(chan struct {
		body []byte
		err  error
	}, 1)
	go func() {
		body, err := io.ReadAll(result.response.Body)
		bodyCh <- struct {
			body []byte
			err  error
		}{body: body, err: err}
	}()

	for _, stage := range []fixtureUpstreamStage{
		fixtureStageFirstByte,
		fixtureStageEvent,
		fixtureStageSemantic,
		fixtureStageIdle,
	} {
		upstream.WaitReached(t, stage)
		assertFixtureResultPending(t, bodyCh, stage)
		upstream.Release(stage)
	}

	bodyResult := <-bodyCh
	if bodyResult.err != nil {
		t.Fatalf("read fixture response: %v", bodyResult.err)
	}
	if body := string(bodyResult.body); !strings.Contains(body, `"text":"2"`) {
		t.Fatalf("fixture response missing semantic event: %q", body)
	}
}

func TestFixtureTestUpstreamCanEndWithUnexpectedEOF(t *testing.T) {
	upstream := newFixtureTestUpstream(t, fixtureUpstreamOptions{AbnormalEOF: true})
	defer upstream.Close()
	upstream.ReleaseAll()

	response, err := upstream.Client().Get(upstream.URL())
	if err != nil {
		t.Fatalf("GET fixture upstream: %v", err)
	}
	defer response.Body.Close()
	_, err = io.ReadAll(response.Body)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error = %v, want unexpected EOF", err)
	}
}

func assertFixtureResultPending[T any](t *testing.T, result <-chan T, stage fixtureUpstreamStage) {
	t.Helper()
	select {
	case <-result:
		t.Fatalf("request completed before %s was released", stage)
	default:
	}
}

const fixtureStageWait = 5 * time.Second
