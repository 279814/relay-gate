package proxy

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
	"github.com/andybalholm/brotli"
)

func encodeRequestFixture(t *testing.T, encoding, plain string) []byte {
	t.Helper()
	if encoding == "gzip" {
		return gzipRequestBody(t, plain)
	}
	var encoded bytes.Buffer
	w := brotli.NewWriterLevel(&encoded, 1)
	if _, err := io.WriteString(w, plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func TestRequestReencodingShadowOnlyDoesNotAuthorizeLiveRewrite(t *testing.T) {
	for _, binding := range []string{"shadow", "different endpoint"} {
		t.Run(binding, func(t *testing.T) {
			var hits atomic.Int32
			hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
			hs.setMappingRoutes("provider-model")
			reg := transform.NewRegistry(10)
			set, err := reg.CreateSet("scope")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: "request_reencode"}}, transform.FailClosed, transform.FailOpen, ""); err != nil {
				t.Fatal(err)
			}
			if binding == "shadow" {
				_, _, err = reg.ShadowSnapshot(set.ID, 100, 1)
			} else {
				_, _, err = reg.PublishSnapshot(set.ID, 100, 2)
			}
			if err != nil {
				t.Fatal(err)
			}
			hs.h.WithTransforms(reg)
			rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gzipRequestBody(t, compressedReqBody)))
			if rec.Code != 415 || hits.Load() != 0 {
				t.Fatalf("binding %s authorized live rewrite: status=%d hits=%d", binding, rec.Code, hits.Load())
			}
		})
	}
}

func TestRequestReencodingShadowDecodesOnlyItsSideCopy(t *testing.T) {
	hs := newHarness(t, nil)
	reg := transform.NewRegistry(10)
	set, err := reg.CreateSet("shadow-copy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{
		{Kind: "request_reencode"},
		{Kind: transform.KindReplaceBytes, From: `"content":"x"`, To: `"content":"shadow"`},
	}, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.ShadowSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)
	gzip := gzipRequestBody(t, compressedReqBody)
	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gzip))
	if rec.Code != 200 || !bytes.Equal(hs.gotReq.body, gzip) {
		t.Fatal("shadow altered live gzip bytes")
	}
	found := shadowPhase(reg, "request")
	if len(found) != 1 || !found[0].OK || found[0].InputHash != transform.HashBytes([]byte(compressedReqBody)) || !strings.Contains(found[0].DiffSummary, "changed=true") {
		t.Fatalf("shadow failed to apply on decoded side copy: %+v", found)
	}
}

func TestRequestReencodingRetriesStartFromOriginalInboundBody(t *testing.T) {
	hs := newMultiHarness(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(503)
			io.WriteString(w, `{"error":"temporary"}`)
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"ok"}]}`)
		},
	)
	reg := transform.NewRegistry(10)
	set, err := reg.CreateSet("retry")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{
		{Kind: "request_reencode"},
		{Kind: transform.KindReplaceBytes, From: "x", To: "xx"},
	}, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	for i, rt := range hs.cfg.snap.RoutesByModelName[1] {
		rt.UpstreamModel = []string{"provider-a", "provider-b"}[i]
		if _, _, err := reg.PublishSnapshot(set.ID, rt.ID, 1); err != nil {
			t.Fatal(err)
		}
	}
	hs.h.WithTransforms(reg)
	encoded := gzipRequestBody(t, compressedReqBody)
	r := httptest.NewRequest("POST", "/v1/messages", bytes.NewReader(encoded))
	r.Header.Set("X-Api-Key", hs.relayPW)
	r.Header.Set("Content-Encoding", "gzip")
	mux := http.NewServeMux()
	hs.h.Routes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	for i, station := range hs.stations {
		hits, keys, bodies := station.stats()
		if hits != 1 || len(keys) != 1 || keys[0] != station.key {
			t.Fatalf("station %d used another station's key: hits=%d keys=%v", i, hits, keys)
		}
		plain, err := decodeTransformBody("gzip", []byte(bodies[0]), MaxRequestBody)
		want := strings.ReplaceAll(compressedReqBody, "x", "xx")
		want = strings.Replace(want, "claude-opus-5", []string{"provider-a", "provider-b"}[i], 1)
		if err != nil || string(plain) != want {
			t.Fatalf("station %d received compounded rewrite=%s err=%v want=%s", i, plain, err, want)
		}
	}
}

func TestRequestReencodingExplicitPublishedBinding(t *testing.T) {
	for _, encoding := range []string{"gzip", "br"} {
		for _, endpoint := range []struct {
			path  string
			proto model.Protocol
		}{
			{"/v1/messages", model.ProtoAnthropic},
			{"/v1/responses", model.ProtoOpenAIResponses},
			{"/v1/chat/completions", model.ProtoOpenAIChat},
			{"/v1/messages/count_tokens", model.ProtoAnthropic},
		} {
			t.Run(encoding+endpoint.path, func(t *testing.T) {
				var hits atomic.Int32
				hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, `{"input_tokens":12345}`)
				})
				hs.setMappingRoutes("provider-model")
				hs.cfg.snap.ModelNames[0].Protocol = endpoint.proto
				hs.publishRequestTransform(t, 100, []transform.Rule{
					{Kind: "request_reencode"},
					{Kind: transform.KindReplaceBytes, From: `"content":"x"`, To: `"content":"changed"`},
					{Kind: transform.KindSetHeader, Name: "X-Transformed", Value: "yes"},
				})
				encoded := encodeRequestFixture(t, encoding, compressedReqBody)
				rec := hs.serve(hs.encodedRequest(endpoint.path, encoding, encoded))
				if rec.Code != 200 || hits.Load() != 1 || rec.Header().Get(headerRelayCountTokens) != "" {
					t.Fatalf("status=%d hits=%d estimate=%q body=%s", rec.Code, hits.Load(), rec.Header().Get(headerRelayCountTokens), rec.Body.String())
				}
				if hs.gotReq.headers.Get("Content-Encoding") != encoding || hs.gotReq.headers.Get("X-Transformed") != "yes" {
					t.Fatalf("wrong upstream headers: %v", hs.gotReq.headers)
				}
				plain, err := decodeTransformBody(encoding, hs.gotReq.body, MaxRequestBody)
				want := strings.Replace(compressedReqBody, "claude-opus-5", "provider-model", 1)
				want = strings.Replace(want, `"content":"x"`, `"content":"changed"`, 1)
				if err != nil || string(plain) != want {
					t.Fatalf("decoded upstream=%s err=%v want=%s", plain, err, want)
				}
				if hs.gotReq.headers.Get("Authorization") != "Bearer "+routeKey(0) || hs.gotReq.headers.Get("X-Api-Key") != "" {
					t.Fatal("request reencoding changed the unique authentication profile")
				}
				if _, open, _ := hs.health.stats(); open != 0 {
					t.Fatalf("leaked concurrency slots: %d", open)
				}
			})
		}
	}
}

func TestRequestTransformCannotOverrideRouteModel(t *testing.T) {
	for _, encoding := range []string{"", "gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			hs := newHarness(t, nil)
			hs.setMappingRoutes("provider-model")
			hs.publishRequestTransform(t, 100, []transform.Rule{
				{Kind: "request_reencode"},
				{Kind: transform.KindSetJSONPointer, Name: "/model", Value: "rule-model"},
			})
			body := []byte(compressedReqBody)
			if encoding != "" {
				body = encodeRequestFixture(t, encoding, compressedReqBody)
			}
			rec := hs.serve(hs.encodedRequest("/v1/messages", encoding, body))
			if rec.Code != 200 {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			got := hs.gotReq.body
			if encoding != "" {
				var err error
				got, err = decodeTransformBody(encoding, got, MaxRequestBody)
				if err != nil {
					t.Fatal(err)
				}
			}
			model, err := ExtractModel(got)
			if err != nil || model != "provider-model" {
				t.Fatalf("rule controlled model=%q err=%v", model, err)
			}
		})
	}
}

func TestRequestTransformRejectsInvalidModelWithVersionFailurePolicy(t *testing.T) {
	for _, policy := range []string{transform.FailClosed, transform.FailOpen} {
		for _, invalid := range []string{`{"removed":true}`, `{"model":"a","model":"b"}`, `{"model":123}`} {
			t.Run(policy+invalid, func(t *testing.T) {
				var hits atomic.Int32
				hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
				hs.setMappingRoutes("provider-model")
				reg := transform.NewRegistry(10)
				set, err := reg.CreateSet("invalid-model")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := reg.UpdateDraft(set.ID, []transform.Rule{
					{Kind: "request_reencode"},
					{Kind: transform.KindReplaceBytes, From: strings.Replace(compressedReqBody, "claude-opus-5", "provider-model", 1), To: invalid},
				}, policy, transform.FailOpen, ""); err != nil {
					t.Fatal(err)
				}
				if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
					t.Fatal(err)
				}
				hs.h.WithTransforms(reg)
				rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gzipRequestBody(t, compressedReqBody)))
				if policy == transform.FailClosed {
					if rec.Code != 502 || hits.Load() != 0 {
						t.Fatalf("invalid model sent: status=%d hits=%d", rec.Code, hits.Load())
					}
				} else {
					if rec.Code != 200 || hits.Load() != 1 {
						t.Fatalf("fail_open failed: status=%d hits=%d", rec.Code, hits.Load())
					}
					plain, err := decodeTransformBody("gzip", hs.gotReq.body, MaxRequestBody)
					want := strings.Replace(compressedReqBody, "claude-opus-5", "provider-model", 1)
					if err != nil || string(plain) != want {
						t.Fatalf("unsafe fail_open body=%s err=%v", plain, err)
					}
				}
			})
		}
	}
}

func TestRequestReencodingHasIndependentDecodedAndEncodedLimits(t *testing.T) {
	// An incompressible body fits the decoded limit but exceeds the encoded
	// limit. This exercises the actual encoder's bounded writer, including Close.
	random := make([]byte, 4096)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{"gzip", "br"} {
		if body, err := encodeRequestBody(encoding, random, len(random)); err == nil || body != nil {
			t.Fatalf("%s failed to bound actual encoded output: bytes=%d err=%v", encoding, len(body), err)
		}
		if body, err := encodeRequestBody(encoding, random, len(random)-1); err == nil || body != nil {
			t.Fatalf("%s failed to bound decoded work: bytes=%d err=%v", encoding, len(body), err)
		}
	}
	var hits atomic.Int32
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	hs.setMappingRoutes("provider-model")
	hs.publishRequestTransform(t, 100, []transform.Rule{{Kind: "request_reencode"}})
	body := `{"model":"claude-opus-5","pad":"` + strings.Repeat("a", transform.MaxBodyBuffer) + `"}`
	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gzipRequestBody(t, body)))
	if rec.Code != 502 || hits.Load() != 0 {
		t.Fatalf("oversize work sent: status=%d hits=%d", rec.Code, hits.Load())
	}
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Fatalf("oversize work leaked %d slots", open)
	}
}

func TestRequestReencodingHalfOpenSkipsUnsentStrictBinding(t *testing.T) {
	hits := []*atomic.Int32{{}, {}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("strict-model", "opted-in-model")
	hs.cfg.settings.HalfOpenEnabled = true
	hs.cfg.settings.RetryMaxAttempts = 1
	hs.health.dead[100], hs.health.dead[101] = true, true
	hs.publishRequestTransform(t, 101, []transform.Rule{{Kind: "request_reencode"}})
	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gzipRequestBody(t, compressedReqBody)))
	if rec.Code != 200 || hits[0].Load() != 0 || hits[1].Load() != 1 {
		t.Fatalf("unsent strict binding consumed recovery: status=%d hits=%d,%d", rec.Code, hits[0].Load(), hits[1].Load())
	}
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Fatalf("half-open leaked %d slots", open)
	}
	for _, id := range []int64{100, 101} {
		release, ok := hs.h.recovery.TryAcquire(id)
		if !ok {
			t.Fatalf("route %d recovery gate leaked", id)
		}
		release()
	}
}

type disableReencodingRouteOnAcquire struct {
	*countingHealth
	route *model.Route
}

func (h disableReencodingRouteOnAcquire) TryAcquire(id int64, limit int) (func(), uint64, bool) {
	release, generation, ok := h.countingHealth.TryAcquire(id, limit)
	if id == h.route.ID {
		h.route.Enabled = false
	}
	return release, generation, ok
}

func TestRequestReencodingLaterHalfOpenStillChecksDisableBeforeSend(t *testing.T) {
	hits := []*atomic.Int32{{}, {}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("strict-model", "opted-in-model")
	hs.cfg.settings.HalfOpenEnabled = true
	hs.health.dead[100], hs.health.dead[101] = true, true
	hs.publishRequestTransform(t, 101, []transform.Rule{{Kind: "request_reencode"}})
	hs.h.health = disableReencodingRouteOnAcquire{hs.health, hs.cfg.snap.RoutesByModelName[1][1]}
	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gzipRequestBody(t, compressedReqBody)))
	if rec.Code != 503 || hits[0].Load() != 0 || hits[1].Load() != 0 {
		t.Fatalf("disabled later recovery sent: status=%d hits=%d,%d", rec.Code, hits[0].Load(), hits[1].Load())
	}
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Fatalf("disable leaked %d slots", open)
	}
}

func TestRequestReencodingAuthorizationIsFrozenAcrossPublishAndRollback(t *testing.T) {
	for _, action := range []string{"publish", "rollback"} {
		for _, initiallyEnabled := range []bool{false, true} {
			name := action + "/disabled"
			if initiallyEnabled {
				name = action + "/enabled"
			}
			t.Run(name, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				var first, unblock sync.Once
				resume := func() { unblock.Do(func() { close(release) }) }
				defer resume()
				hs := newMultiHarness(t,
					func(w http.ResponseWriter, r *http.Request) {
						first.Do(func() { close(entered); <-release })
						w.WriteHeader(503)
						io.WriteString(w, `{"error":"temporary"}`)
					},
					func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"ok"}]}`)
					},
				)
				hs.cfg.snap.RoutesByModelName[1][1].UpstreamModel = "second-provider"
				reg := transform.NewRegistry(20)
				set, err := reg.CreateSet("frozen-authorization")
				if err != nil {
					t.Fatal(err)
				}
				publish := func(enabled bool) int64 {
					t.Helper()
					rules := []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Published", Value: "yes"}}
					if enabled {
						rules = append(rules, transform.Rule{Kind: "request_reencode"})
					}
					if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
						t.Fatal(err)
					}
					_, version, err := reg.PublishSnapshot(set.ID, 200, 1)
					if err != nil {
						t.Fatal(err)
					}
					return version.ID
				}
				var previous int64
				if action == "rollback" {
					previous = publish(!initiallyEnabled)
				}
				publish(initiallyEnabled)
				hs.h.WithTransforms(reg)
				mux := http.NewServeMux()
				hs.h.Routes(mux)
				gateway := httptest.NewServer(mux)
				defer gateway.Close()
				defer resume()
				client := &http.Client{Timeout: 5 * time.Second}
				encoded := gzipRequestBody(t, compressedReqBody)
				send := func() int {
					r, _ := http.NewRequest("POST", gateway.URL+"/v1/messages", bytes.NewReader(encoded))
					r.Header.Set("X-Api-Key", hs.relayPW)
					r.Header.Set("Content-Encoding", "gzip")
					res, err := client.Do(r)
					if err != nil {
						return 0
					}
					defer res.Body.Close()
					io.Copy(io.Discard, res.Body)
					return res.StatusCode
				}
				finished := make(chan int, 1)
				go func() { finished <- send() }()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("first upstream was not entered")
				}
				if action == "rollback" {
					if _, err := reg.Rollback(200, 1, previous); err != nil {
						t.Fatal(err)
					}
				} else {
					publish(!initiallyEnabled)
				}
				resume()
				wantOld, wantNew := 415, 200
				if initiallyEnabled {
					wantOld, wantNew = 200, 415
				}
				if status := <-finished; status != wantOld {
					t.Fatalf("in-flight authorization changed: got=%d want=%d", status, wantOld)
				}
				if status := send(); status != wantNew {
					t.Fatalf("new request missed authorization: got=%d want=%d", status, wantNew)
				}
				hs.assertHits(t, 2, 1)
			})
		}
	}
}
