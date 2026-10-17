package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
)

type rejectionEOFBody struct {
	io.ReadCloser
	once sync.Once
	eof  chan struct{}
}

func (b *rejectionEOFBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.once.Do(func() { close(b.eof) })
	}
	return n, err
}

func TestModelEarlyRejectionSmallClosePostDelivers503AndDiscardsBody(t *testing.T) {
	for _, kind := range []string{"frozen", "maintenance", "paused"} {
		t.Run(kind, func(t *testing.T) {
			hs := newHarness(t, nil)
			switch kind {
			case "frozen":
				hs.h.admission.frozen = true
			case "maintenance":
				hs.h.WithRunState(maintSnap{snap: runstate.Snapshot{State: model.RunStateRunning, Maintenance: true}})
			case "paused":
				hs.cfg.state = model.RunStatePaused
			}
			mux := http.NewServeMux()
			hs.h.Routes(mux)
			eof := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Body = &rejectionEOFBody{ReadCloser: r.Body, eof: eof}
				mux.ServeHTTP(w, r)
			}))
			defer server.Close()
			r, err := http.NewRequest("POST", server.URL+"/v1/messages", strings.NewReader(`{"model":"claude-opus-5","messages":[],"private":"discard-fixture-marker"}`))
			if err != nil {
				t.Fatal(err)
			}
			r.Close = true
			r.Header.Set("X-Api-Key", hs.relayPW)
			response, err := server.Client().Do(r)
			if err != nil {
				t.Fatalf("normal small POST lost its real 503 response: %v", err)
			}
			defer response.Body.Close()
			wire, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 503 {
				t.Fatalf("status=%d", response.StatusCode)
			}
			if strings.Contains(string(wire), "discard-fixture") {
				t.Fatal("rejection leaked private body")
			}
			select {
			case <-eof:
			default:
				t.Fatal("small rejected body remained unread")
			}
			if len(hs.health.acquired) != 0 || hs.gotReq.method != "" {
				t.Fatal("rejected request acquired route or reached upstream")
			}
		})
	}
}
