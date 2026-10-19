package proxy

import (
	"bytes"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/transform"
)

func TestCompressedRequestLocalSkipContinuesToAvailablePrefix(t *testing.T) {
	hs := newHarness(t, nil)
	hs.setMappingRoutes("provider-model", "")
	exact := hs.cfg.snap.ModelNames[0]
	prefix := &model.ModelName{ID: 2, Name: "claude-", Protocol: model.ProtoAnthropic, MatchMode: model.MatchPrefix, Enabled: true}
	routes := hs.cfg.snap.RoutesByModelName[1]
	routes[1].ModelNameID = 2
	hs.cfg.snap = router.BuildSnapshot([]*model.ModelName{exact, prefix}, []*model.Upstream{hs.cfg.snap.Upstreams[10], hs.cfg.snap.Upstreams[11]}, routes)
	encoded := gzipRequestBody(t, compressedReqBody)
	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", encoded))
	if rec.Code != 200 || !bytes.Equal(hs.gotReq.body, encoded) || hs.gotReq.headers.Get("Authorization") != "Bearer "+routeKey(1) {
		t.Fatalf("available prefix was skipped: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

type fallbackRequestLogs struct{ rows []*model.RequestLog }

func (l *fallbackRequestLogs) Record(row *model.RequestLog) { l.rows = append(l.rows, row) }

func TestRetryKeepsUpstreamResponseWhenLaterCandidatesCannotPrepare(t *testing.T) {
	for _, skip := range []string{"strict mapping", "fail_closed"} {
		t.Run(skip, func(t *testing.T) {
			var hits atomic.Int32
			const original = `{"error":{"type":"overloaded_error","message":"original-upstream-error"}}`
			hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("X-Upstream-Response", "original")
				w.WriteHeader(503)
				io.WriteString(w, original)
			})
			hs.setMappingRoutes("", "")
			if skip == "strict mapping" {
				hs.cfg.snap.RoutesByModelName[1][1].UpstreamModel = "provider-model"
			} else {
				hs.publishRequestTransform(t, 101, []transform.Rule{{Kind: transform.KindJSONPatchRemove, Name: "/missing"}})
			}
			hs.cfg.settings.RetryMaxAttempts = 2
			logs := &fallbackRequestLogs{}
			hs.h.WithLogSink(logs)
			r := hs.anthropicRequest(compressedReqBody)
			if skip == "strict mapping" {
				r = hs.encodedRequest("/v1/messages", "gzip", gzipRequestBody(t, compressedReqBody))
			}
			rec := hs.serve(r)
			if rec.Code != 503 || rec.Body.String() != original || rec.Header().Get("X-Upstream-Response") != "original" || hits.Load() != 1 {
				t.Fatalf("unsent candidate replaced upstream response: status=%d body=%s hits=%d", rec.Code, rec.Body.String(), hits.Load())
			}
			if len(logs.rows) != 1 || logs.rows[0].Attempts != 1 || logs.rows[0].Retried {
				t.Fatalf("unsent local failure counted as a retry: %+v", logs.rows)
			}
			if _, open, _ := hs.health.stats(); open != 0 {
				t.Fatalf("fallback leaked %d slots", open)
			}
		})
	}
}

func TestCountTokensUnsentMappingDoesNotConsumeUnknownAttempt(t *testing.T) {
	hits := []*atomic.Int32{{}, {}}
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		for i, hit := range hits {
			if r.Header.Get("Authorization") == "Bearer "+routeKey(i) {
				hit.Add(1)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"input_tokens":12345}`)
	})
	hs.setMappingRoutes("strict-model", "")
	rec := hs.serve(hs.encodedRequest("/v1/messages/count_tokens", "gzip", gzipRequestBody(t, compressedReqBody)))
	if rec.Code != 200 || rec.Header().Get(headerRelayCountTokens) != "" || hits[0].Load() != 0 || hits[1].Load() != 1 {
		t.Fatalf("unsent mapping consumed unknown attempt: status=%d estimated=%q hits=%d,%d body=%s", rec.Code, rec.Header().Get(headerRelayCountTokens), hits[0].Load(), hits[1].Load(), rec.Body.String())
	}
}

func TestCountTokensSentUnknownFailureConsumesItsOnlyUnknownAttempt(t *testing.T) {
	hits := []*atomic.Int32{{}, {}}
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		for i, hit := range hits {
			if r.Header.Get("Authorization") == "Bearer "+routeKey(i) {
				hit.Add(1)
			}
		}
		w.WriteHeader(503)
		io.WriteString(w, `{"error":"temporary"}`)
	})
	hs.setMappingRoutes("", "")
	rec := hs.serve(hs.countTokensRequest(compressedReqBody))
	if rec.Code != 200 || rec.Header().Get(headerRelayCountTokens) != "estimated" || hits[0].Load() != 1 || hits[1].Load() != 0 {
		t.Fatalf("sent unknown tried multiple candidates: status=%d estimated=%q hits=%d,%d", rec.Code, rec.Header().Get(headerRelayCountTokens), hits[0].Load(), hits[1].Load())
	}
}

func TestRetrySkipsLocalFailureAndReleasesPreviousBeforeReplacementSend(t *testing.T) {
	var hs *harness
	hits := []*atomic.Int32{{}, {}, {}}
	var openDuringReplacement atomic.Int32
	hs = newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		for i, hit := range hits {
			if r.Header.Get("Authorization") != "Bearer "+routeKey(i) {
				continue
			}
			hit.Add(1)
			if i == 0 {
				w.WriteHeader(503)
				io.WriteString(w, `{"error":"temporary"}`)
				return
			}
			_, open, _ := hs.health.stats()
			openDuringReplacement.Store(int32(open))
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"ok"}]}`)
			return
		}
	})
	hs.setMappingRoutes("", "", "")
	hs.cfg.settings.RetryMaxAttempts = 2
	hs.publishRequestTransform(t, 101, []transform.Rule{{Kind: transform.KindJSONPatchRemove, Name: "/missing"}})
	logs := &fallbackRequestLogs{}
	hs.h.WithLogSink(logs)
	rec := hs.serve(hs.anthropicRequest(compressedReqBody))
	if rec.Code != 200 || hits[0].Load() != 1 || hits[1].Load() != 0 || hits[2].Load() != 1 || openDuringReplacement.Load() != 1 {
		t.Fatalf("replacement attempts or concurrency wrong: status=%d hits=%d,%d,%d open=%d", rec.Code, hits[0].Load(), hits[1].Load(), hits[2].Load(), openDuringReplacement.Load())
	}
	if len(logs.rows) != 2 || logs.rows[0].RouteID != 100 || !logs.rows[0].Retried || logs.rows[1].RouteID != 102 || logs.rows[1].Attempt != 2 || logs.rows[1].Attempts != 2 {
		t.Fatalf("local skip changed network-attempt logs: %+v", logs.rows)
	}
	if group := hs.sink.one(t); len(group.Attempts) != 2 || group.Attempts[0].RouteID != 100 || group.Attempts[1].RouteID != 102 {
		t.Fatalf("samples include an unsent local candidate: %+v", group.Attempts)
	}
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Fatalf("replacement leaked %d slots", open)
	}
}
