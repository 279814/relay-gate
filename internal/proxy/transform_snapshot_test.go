package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
)

func TestRetryUsesRequestStartTransformViewAcrossPublishAndRollback(t *testing.T) {
	for _, change := range []string{"publish", "rollback", "first binding", "shadow", "detach", "prefix retry"} {
		t.Run(change, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var first sync.Once
			secondHeaders := make(chan http.Header, 2)
			hs := newMultiHarness(t, func(w http.ResponseWriter, r *http.Request) {
				first.Do(func() { close(entered); <-release })
				w.WriteHeader(http.StatusServiceUnavailable)
				io.WriteString(w, `{"error":{"type":"server_error"}}`)
			}, func(w http.ResponseWriter, r *http.Request) {
				secondHeaders <- r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"complete"}]}`)
			})
			if change == "prefix retry" {
				// SelectExcluding can continue from an exhausted exact match to a
				// prefix ModelName; the request view must include that candidate.
				routes := hs.cfg.snap.RoutesByModelName[1]
				routes[1].ModelNameID = 2
				hs.cfg.snap.RoutesByModelName[1] = routes[:1]
				hs.cfg.snap.RoutesByModelName[2] = routes[1:]
				hs.cfg.snap.ModelNames = append(hs.cfg.snap.ModelNames, &model.ModelName{ID: 2, Name: "claude-", Protocol: model.ProtoAnthropic, MatchMode: model.MatchPrefix, Enabled: true})
			}
			reg := transform.NewRegistry(32)
			set, err := reg.CreateSet("request-snapshot")
			if err != nil {
				t.Fatal(err)
			}
			publish := func(value string, shadow bool) int64 {
				t.Helper()
				if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Snapshot", Value: value}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
					t.Fatal(err)
				}
				var v *transform.Version
				var err error
				if shadow {
					_, v, err = reg.ShadowSnapshot(set.ID, 200, 1)
				} else {
					_, v, err = reg.PublishSnapshot(set.ID, 200, 1)
				}
				if err != nil {
					t.Fatal(err)
				}
				return v.ID
			}
			oldVersion := publish("old", false)
			want, nextWant := "old", "new"
			if change == "rollback" {
				publish("new", false)
				want, nextWant = "new", "old"
			}
			if change == "first binding" {
				if err := reg.DetachRouteBindingsAround([]int64{200}, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
				want = ""
			}
			shadowVersion := publish("shadow-old", true)
			hs.h.WithTransforms(reg)
			mux := http.NewServeMux()
			hs.h.Routes(mux)
			gateway := httptest.NewServer(mux)
			defer gateway.Close()
			var releaseOnce sync.Once
			resume := func() { releaseOnce.Do(func() { close(release) }) }
			defer resume()
			type response struct {
				status int
				header http.Header
				body   []byte
				err    error
			}
			send := func() response {
				req, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/messages", strings.NewReader(hs.req()))
				req.Header.Set("X-Api-Key", hs.relayPW)
				res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
				if err != nil {
					return response{err: err}
				}
				defer res.Body.Close()
				body, err := io.ReadAll(res.Body)
				return response{res.StatusCode, res.Header, body, err}
			}
			finished := make(chan response, 1)
			go func() { finished <- send() }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("first station was not entered")
			}
			if change == "rollback" {
				if _, err := reg.Rollback(200, 1, oldVersion); err != nil {
					t.Fatal(err)
				}
			} else if change == "detach" {
				if err := reg.DetachRouteBindingsAround([]int64{200}, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
				nextWant = ""
			} else if change != "shadow" {
				publish("new", false)
			} else {
				nextWant = want
			}
			latestShadow := publish("shadow-new", true)
			resume()
			got := <-finished
			if got.err != nil || got.status != 200 || !strings.Contains(string(got.body), "complete") {
				t.Fatalf("forward result=%+v", got)
			}
			if header := <-secondHeaders; header.Get("X-Snapshot") != want || got.header.Get("X-Snapshot") != want {
				t.Errorf("in-flight retry read a new published version: upstream=%q client=%q want=%q", header.Get("X-Snapshot"), got.header.Get("X-Snapshot"), want)
			}
			for _, phase := range []string{"request", "response"} {
				recs := waitSnapshotShadowPhase(t, reg, phase, 1)
				if len(recs) != 1 || recs[0].VersionID != shadowVersion {
					t.Errorf("%s shadow changed in flight: %+v want version %d", phase, recs, shadowVersion)
				}
			}
			got = send()
			if got.err != nil || got.status != 200 {
				t.Fatalf("new request=%+v", got)
			}
			if header := <-secondHeaders; header.Get("X-Snapshot") != nextWant || got.header.Get("X-Snapshot") != nextWant {
				t.Errorf("new request missed new published version: upstream=%q client=%q want=%q", header.Get("X-Snapshot"), got.header.Get("X-Snapshot"), nextWant)
			}
			for _, phase := range []string{"request", "response"} {
				recs := waitSnapshotShadowPhase(t, reg, phase, 2)
				if recs[0].VersionID != latestShadow {
					t.Errorf("new request did not use latest %s shadow: %+v", phase, recs)
				}
			}
			hs.assertHits(t, 2, 2)
		})
	}
}

func waitSnapshotShadowPhase(t *testing.T, reg *transform.Registry, phase string, count int) []transform.ExecutionRecord {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		records := shadowPhase(reg, phase)
		if len(records) >= count {
			return records
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s shadow records=%d want=%d", phase, len(records), count)
		}
		time.Sleep(time.Millisecond)
	}
}
